// This package provides a client for the NVDA remote protocol, allowing you to connect to an NVDA remote server and send commands or receive events.
// NVDA remote is an addon for NVDA (NonVisual Desktop Access), a screen reader for Windows. It allows you to help other NVDA users by letting them share there speech output and streaming keyboard presses to the remote client.
// This app works through a server. The most popular server is nvdaremote.com.
// Both clients connect to the same server, one as a controller and the other as a controled client.
// The controller sends key presses to the controlled client and receives speech output from it.
// with this library you can create nvda remote clients for any OSes, allowing not only NVDA users to help each other, but also other screen readers users to help NVDA users.
// Also you can make games and other applications that use NVDA remote protocol to send speech output and receive key presses from the user.
// This library is not affiliated with NVDA or nvdaremote.com in any way. It is just a client for the NVDA remote protocol.
package nvda_remote_go

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/denizsincar29/nvda_remote_go/fingerprints"
)

const DEFAULT_PORT = "6837"

type NVDARemoteClient struct {
	// Configuration (set before CheckServer)
	host           string
	port           string
	channel        string
	connType       string
	logger         *slog.Logger
	fpManager      *fingerprints.FingerprintManager
	targetHostPort string // Combined host:port

	// Connection State (managed internally)
	conn               *tls.Conn
	state              ClientState
	verificationStatus VerificationStatus
	serverFingerprint  string // The actual fingerprint presented by the server
	lastError          error  // Stores the error from CheckServer or Connect

	// Communication (initialized in Connect)
	eventChan chan Packet
	sendChan  chan []byte
	errorChan chan error
	closeChan chan struct{} // Signals initiated closure
	stopOnce  sync.Once     // Ensures close logic runs once
	wg        sync.WaitGroup

	// Handlers
	eventHandler func(Packet)
}

// --- Client Initialization and Connection Flow ---

// NewClient prepares a client instance but doesn't connect yet.
func NewClient(host, port, channel, connType string, lgr *slog.Logger, fm *fingerprints.FingerprintManager) (*NVDARemoteClient, error) {
	if host == "" {
		return nil, errors.New("host cannot be empty")
	}
	if port == "" {
		port = DEFAULT_PORT
	}
	if lgr == nil {
		lgr = slog.Default()
	}
	if fm == nil {
		return nil, errors.New("fingerprint manager is required")
	}
	if channel == "" {
		return nil, errors.New("channel cannot be empty")
	}
	if connType != "master" && connType != "slave" {
		return nil, fmt.Errorf("invalid connType: %s (must be 'master' or 'slave')", connType)
	}

	return &NVDARemoteClient{
		host:               host,
		port:               port,
		channel:            channel,
		connType:           connType,
		logger:             lgr,
		fpManager:          fm,
		targetHostPort:     net.JoinHostPort(host, port),
		state:              StateIdle,
		verificationStatus: VerificationNotChecked,
	}, nil
}

// CheckServer attempts a TLS connection to verify the server's certificate fingerprint.
// It populates ServerFingerprint() and VerificationStatus() but does NOT start read/write loops.
// Returns an error only if the TCP connection or initial TLS handshake fails,
// or if the certificate cannot be parsed. Fingerprint status itself doesn't cause an error here.
func (c *NVDARemoteClient) CheckServer() error {
	if c.state != StateIdle {
		return fmt.Errorf("CheckServer can only be called in StateIdle (current: %v)", c.state)
	}
	c.logger.Debug("Checking server connection and fingerprint", "host", c.targetHostPort)

	// Use local variables to store results from the callback via closure
	var presentedFingerprint string
	var checkStatus VerificationStatus = VerificationError // Default to error
	var certParseErr error

	conf := &tls.Config{
		ServerName: c.host,
		// InsecureSkipVerify must be FALSE to get certificates in VerifyPeerCertificate
		InsecureSkipVerify: false,
		// Custom verification logic
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// This function runs *after* the basic TLS handshake succeeds
			// but *before* Dial returns. Its goal here is to *check* the fingerprint,
			// not necessarily to *fail* the Dial based on it.

			if len(rawCerts) == 0 {
				certParseErr = errors.New("no peer certificates presented by server")
				checkStatus = VerificationError
				c.logger.Error("VerifyPeerCertificate", "error", certParseErr)
				return certParseErr // Return error if cert is fundamentally wrong/missing
			}

			leafCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				certParseErr = fmt.Errorf("failed to parse server's leaf certificate: %w", err)
				checkStatus = VerificationError
				c.logger.Error("VerifyPeerCertificate", "error", certParseErr)
				return certParseErr // Return error if cert is fundamentally wrong/missing
			}

			// Calculate presented fingerprint
			presentedFingerprint = fingerprints.CalculateSha256Fingerprint(leafCert)

			// Look up expected fingerprint
			expectedFingerprint, known := c.fpManager.Get(c.targetHostPort)

			// Determine status
			if !known {
				checkStatus = VerificationUnknown
				c.logger.Warn("VerifyPeerCertificate: Unknown fingerprint", "host", c.targetHostPort, "fingerprint", presentedFingerprint)
			} else if !strings.EqualFold(expectedFingerprint, presentedFingerprint) {
				checkStatus = VerificationMismatch
				c.logger.Warn("VerifyPeerCertificate: Fingerprint mismatch", "host", c.targetHostPort, "expected", expectedFingerprint, "got", presentedFingerprint)
			} else {
				checkStatus = VerificationOK
				c.logger.Info("VerifyPeerCertificate: Fingerprint OK", "host", c.targetHostPort, "fingerprint", presentedFingerprint)
			}

			// IMPORTANT: Return nil here to allow tls.Dial to succeed
			// regardless of the fingerprint status. We capture the status
			// in the 'checkStatus' closure variable.
			return nil
		},
	}

	// Attempt the dial
	dialer := &net.Dialer{Timeout: 10 * time.Second} // Add a timeout
	rawConn, err := dialer.Dial("tcp", c.targetHostPort)
	if err != nil {
		c.logger.Error("TCP Dial failed", "host", c.targetHostPort, "error", err)
		c.state = StateClosed
		c.lastError = err
		return err // Network error
	}

	// Perform TLS handshake
	conn := tls.Client(rawConn, conf)
	err = conn.Handshake()
	if err != nil {
		// This 'err' could be the certParseErr returned from VerifyPeerCertificate
		// or another TLS handshake error.
		_ = rawConn.Close() // Close the underlying TCP conn if TLS fails
		c.logger.Error("TLS Handshake failed", "host", c.targetHostPort, "error", err)
		c.state = StateClosed
		// Prioritize cert parse error if it happened
		if certParseErr != nil {
			c.lastError = certParseErr
			return certParseErr
		}
		c.lastError = err
		return err
	}

	// Handshake succeeded, update client state based on callback results
	c.conn = conn
	c.serverFingerprint = presentedFingerprint
	c.verificationStatus = checkStatus
	c.state = StateChecked
	if c.verificationStatus == VerificationOK {
		c.state = StateTrusted // Can proceed directly to Connect if OK
	}
	c.logger.Info("CheckServer completed", "host", c.targetHostPort, "status", c.verificationStatus, "fingerprint", c.serverFingerprint)
	return nil // Success (CheckServer itself succeeded)
}

// ServerFingerprint returns the SHA256 fingerprint presented by the server during CheckServer.
// Returns an empty string if CheckServer hasn't run or failed before getting the cert.
func (c *NVDARemoteClient) ServerFingerprint() string {
	return c.serverFingerprint
}

// VerificationStatus returns the result of the fingerprint check performed by CheckServer.
func (c *NVDARemoteClient) VerificationStatus() VerificationStatus {
	return c.verificationStatus
}

// State returns the current state of the client connection process.
func (c *NVDARemoteClient) State() ClientState {
	return c.state
}

// LastError returns the last error encountered during CheckServer or Connect.
func (c *NVDARemoteClient) LastError() error {
	return c.lastError
}

// Trust explicitly marks the server's presented fingerprint as trusted for this session
// and attempts to save it using the FingerprintManager for future connections.
// This should only be called after CheckServer resulted in VerificationUnknown or VerificationMismatch.
func (c *NVDARemoteClient) Trust() error {
	if c.state != StateChecked {
		return fmt.Errorf("Trust can only be called after CheckServer succeeded (state is %v)", c.state)
	}
	if c.verificationStatus == VerificationOK {
		c.logger.Warn("Trust() called but verification status was already OK.")
		c.state = StateTrusted // Ensure state is correct
		return nil             // Nothing to do
	}
	if c.serverFingerprint == "" {
		return errors.New("Trust called but server fingerprint is missing (CheckServer likely failed early)")
	}

	c.logger.Info("Trusting server fingerprint", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	err := c.fpManager.Add(c.targetHostPort, c.serverFingerprint)
	if err != nil {
		c.logger.Error("Failed to save trusted fingerprint", "host", c.targetHostPort, "error", err)
		c.lastError = fmt.Errorf("failed to save trusted fingerprint: %w", err)
		// Don't change state to Trusted if save failed, application might want to handle this
		return c.lastError
	}

	// Mark as trusted for this session
	c.state = StateTrusted
	c.verificationStatus = VerificationOK // Reflect that it's now considered OK
	return nil
}

// Connect finalizes the connection by starting the communication loops and sending the handshake.
// This MUST be called after CheckServer has run and the state is StateTrusted
// (either initially verified or after calling Trust()).
func (c *NVDARemoteClient) Connect() error {
	if c.state != StateTrusted {
		err := fmt.Errorf("Connect can only be called when state is StateTrusted (current: %v)", c.state)
		c.lastError = err
		// Consider closing the connection if Connect is called inappropriately?
		// If c.conn != nil { c.Close() }
		return err
	}
	if c.conn == nil {
		err := errors.New("Connect called but TLS connection is missing")
		c.lastError = err
		c.state = StateClosed // Critical internal error
		return err
	}

	c.logger.Info("Connecting and starting protocol loops", "host", c.targetHostPort)
	c.state = StateConnecting

	// Initialize communication channels and waitgroup
	c.eventChan = make(chan Packet, 1000)
	c.sendChan = make(chan []byte, 100)
	c.errorChan = make(chan error, 10) // Buffered error channel
	c.closeChan = make(chan struct{})
	c.stopOnce = sync.Once{} // Reset stopOnce for this connection attempt
	c.wg = sync.WaitGroup{}

	// Start background loops
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()

	// Send initial NVDA protocol packets
	handshake, joinpacket := NewJoinPackets(c.channel, c.connType)
	c.logger.Debug("Sending handshake and join packet", "handshake", handshake, "joinpacket", joinpacket)
	err := c.Send(handshake)
	if err != nil {
		c.logger.Error("Failed to send handshake packet", "error", err)
		c.lastError = fmt.Errorf("failed to send handshake: %w", err)
		c.Close()
		return c.lastError
	}
	err = c.Send(joinpacket)
	if err != nil {
		c.logger.Error("Failed to send join packet", "error", err)
		c.lastError = fmt.Errorf("failed to send join packet: %w", err)
		c.Close()
		return c.lastError
	}

	c.state = StateConnected
	c.logger.Info("Client connected successfully", "host", c.targetHostPort)
	return nil
}

// --- Communication and Teardown ---

// signalClose initiates the shutdown sequence.
func (c *NVDARemoteClient) signalClose() {
	c.stopOnce.Do(func() {
		c.logger.Debug("signalClose called")
		if c.state != StateClosed {
			c.state = StateClosed // Mark as closed immediately
			close(c.closeChan)    // Signal goroutines to stop
		}
	})
}

// Close gracefully shuts down the client connection and loops.
// Safe to call multiple times or on partially initialized clients.
func (c *NVDARemoteClient) Close() {
	c.logger.Debug("Close() called", "currentState", c.state)
	// Signal loops to stop FIRST, especially before closing conn
	c.signalClose()

	// Close the underlying connection. This will interrupt blocking Read/Write calls.
	if c.conn != nil {
		err := c.conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) { // Ignore "already closed" errors
			c.logger.Warn("Error closing TLS connection", "error", err)
			if c.lastError == nil {
				c.lastError = fmt.Errorf("error during close: %w", err)
			}
		}
		c.conn = nil // Prevent reuse
	}

	// Wait for the readLoop and writeLoop goroutines to finish.
	// Add a timeout to prevent hanging indefinitely if a loop is stuck.
	waitChan := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		c.logger.Debug("Background goroutines finished.")
	case <-time.After(5 * time.Second): // Adjust timeout as needed
		c.logger.Error("Timeout waiting for background goroutines to finish during Close.")
		if c.lastError == nil {
			c.lastError = errors.New("timeout waiting for goroutines during close")
		}
	}

	// Close channels only after ensuring goroutines using them have stopped.
	if c.sendChan != nil {
		close(c.sendChan)
		c.sendChan = nil
	}
	if c.eventChan != nil {
		close(c.eventChan)
		c.eventChan = nil
	}
	if c.errorChan != nil {
		// Drain briefly before closing? Or just close? Closing is usually sufficient.
		close(c.errorChan)
		c.errorChan = nil
	}
	c.logger.Info("NVDA remote client closed.", "host", c.targetHostPort)
}

// --- Getters for Channels (should only be used after Connect succeeds) ---

// Events returns a channel for receiving packets. Read from this channel until it's closed.
// Returns nil if the client is not in a connected state.
func (c *NVDARemoteClient) Events() <-chan Packet {
	if c.state != StateConnected && c.state != StateConnecting { // Be slightly lenient for setup race?
		return nil // Or return a closed channel? nil is clearer maybe.
	}
	return c.eventChan
}

// Errors returns a channel for receiving asynchronous errors. Read from this channel until it's closed.
// Returns nil if the client is not in a connected state.
func (c *NVDARemoteClient) Errors() <-chan error {
	if c.state != StateConnected && c.state != StateConnecting && c.errorChan != nil {
		// Allow access even if not fully connected if errorChan was somehow created
		return c.errorChan
	}
	if c.state != StateConnected && c.state != StateConnecting {
		return nil
	}
	return c.errorChan
}

// SetEventHandler sets the callback for handling incoming packets directly.
// If set, packets will not be sent to the Events() channel.
func (c *NVDARemoteClient) SetEventHandler(handler func(Packet)) {
	c.eventHandler = handler
}

// --- Internal Loop Implementations (Mostly unchanged, check error handling) ---

func (c *NVDARemoteClient) readLoop() {
	defer c.wg.Done()
	defer c.signalClose() // Ensure shutdown on exit
	c.logger.Debug("Read loop started")

	tempBuffer := make([]byte, 1024)
	buffer := make([]byte, 0, 16384)

	for {
		select {
		case <-c.closeChan:
			c.logger.Debug("Read loop received close signal, exiting.")
			return
		default:
			err := c.conn.SetReadDeadline(time.Now().Add(1 * time.Second)) // Use a slightly longer deadline?
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					c.logger.Error("Read loop: Error setting read deadline", "error", err)
					c.sendError(fmt.Errorf("read deadline error: %w", err)) // Send non-fatal error
				}
				// If closed, loop will exit via closeChan or read error
			}

			n, err := c.conn.Read(tempBuffer)
			if err != nil {
				netErr, ok := err.(net.Error)
				if ok && netErr.Timeout() {
					continue // Timeout is expected, continue loop
				}
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") || errors.Is(err, os.ErrClosed) || strings.Contains(err.Error(), "broken pipe") {
					c.logger.Debug("Read loop: Connection closed or broken pipe, exiting.")
					// Don't send error for expected closure. signalClose will handle state.
					// signalClose() // Already deferred
					return
				}
				// Log and send other errors, then exit loop
				c.logger.Error("Read loop: Error reading from connection", "error", err)
				c.sendError(fmt.Errorf("read error: %w", err))
				// signalClose() // Already deferred
				return
			}

			if n == 0 {
				continue // Should not happen with blocking read unless connection closed
			}

			buffer = append(buffer, tempBuffer[:n]...)

			for {
				newLineIndex := strings.Index(string(buffer), "\n")
				if newLineIndex == -1 {
					break // Need more data
				}
				data := buffer[:newLineIndex]
				buffer = buffer[newLineIndex+1:]

				if len(data) == 0 {
					continue
				} // Skip empty lines

				c.logger.Log(context.Background(), slog.LevelDebug, "Received data", "data", string(data)) // Use lower level for raw data
				event, err := ParsePacket(data)
				if err != nil {
					c.logger.Warn("Read loop: Error parsing packet", "error", err, "raw_data", string(data))
					c.sendError(fmt.Errorf("packet parsing error: %w for data %q", err, string(data)))
					continue // Try next packet
				}

				if _, ok := event.(*PingPacket); ok {
					continue
				} // Skip pings

				if c.eventHandler != nil {
					// Run handler in goroutine to avoid blocking read loop? Needs careful thought.
					// If handler is quick, direct call is fine.
					c.eventHandler(event)
				} else {
					select {
					case c.eventChan <- event:
					case <-c.closeChan:
						c.logger.Debug("Read loop: Closing, discarding event.")
						return
					default:
						c.logger.Warn("Read loop: Event channel full, dropping event", "packet_type", fmt.Sprintf("%T", event))
						// Maybe send an error indicating buffer overflow?
						c.sendError(errors.New("event channel overflow"))
					}
				}
			}
			// Prevent buffer growing indefinitely
			if len(buffer) > 32*1024 {
				c.logger.Error("Read buffer exceeded limit, clearing buffer and closing connection.", "size", len(buffer))
				c.sendError(errors.New("read buffer overflow"))
				// signalClose() // Already deferred
				c.conn.Close() // Force close connection
				return
			}
		}
	}
}

func (c *NVDARemoteClient) writeLoop() {
	defer c.wg.Done()
	defer c.signalClose() // Ensure shutdown on exit
	c.logger.Debug("Write loop started")
	for {
		select {
		case <-c.closeChan:
			c.logger.Debug("Write loop received close signal, exiting.")
			return
		case data, ok := <-c.sendChan:
			if !ok {
				c.logger.Debug("Write loop: Send channel closed, exiting.")
				return // Exit if channel is closed
			}

			err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
					c.logger.Error("Write loop: Error setting write deadline", "error", err)
					c.sendError(fmt.Errorf("write deadline error: %w", err))
				}
				return
			}

			_, err = c.conn.Write(append(data, '\n'))
			if err != nil {
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "broken pipe") {
					c.logger.Debug("Write loop: Connection closed or broken pipe, exiting.")
					return
				}
				c.logger.Error("Write loop: Error writing to connection", "error", err)
				c.sendError(fmt.Errorf("write error: %w", err))
				return // Exit loop on write error
			}
			c.logger.Log(context.Background(), slog.LevelDebug, "Sent data", "data", string(data)) // Lower level for raw data

		}
	}
}

// Send queues a packet to be sent to the server.
// Returns an error if the client is not connected or the send channel is full/closed.
func (c *NVDARemoteClient) Send(data Packet) error {
	if c.state != StateConnected {
		return fmt.Errorf("cannot send packet, client state is %v (must be StateConnected)", c.state)
	}
	if c.sendChan == nil {
		return errors.New("cannot send packet, send channel is not initialized")
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		c.logger.Error("Send: Failed to marshal packet", "error", err, "packet_type", fmt.Sprintf("%T", data))
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	select {
	case c.sendChan <- jsonData:
		// Optionally log here at a lower level if needed
		return nil
	case <-c.closeChan:
		c.logger.Warn("Send: Cannot send packet, client is closing or closed")
		return errors.New("client closed")
	default:
		// Non-blocking check failed, try blocking with timeout
		timer := time.NewTimer(100 * time.Millisecond) // Short timeout
		select {
		case c.sendChan <- jsonData:
			timer.Stop()
			return nil
		case <-c.closeChan:
			timer.Stop()
			c.logger.Warn("Send: Cannot send packet, client closed during wait")
			return errors.New("client closed")
		case <-timer.C:
			c.logger.Error("Send: Failed to send packet, send channel full (timeout)")
			// Send error to error channel?
			c.sendError(errors.New("send channel full (timeout)"))
			return errors.New("send channel full (timeout)")
		}
	}
}

// sendError safely sends an error to the error channel if initialized.
func (c *NVDARemoteClient) sendError(err error) {
	if err == nil || c.errorChan == nil {
		return
	}
	// Use non-blocking send to avoid deadlocking if error channel is full
	select {
	case c.errorChan <- err:
	case <-c.closeChan: // Don't block if closing
	default:
		c.logger.Warn("Error channel full, dropping error", "dropped_error", err)
	}
}

// SendSpeech sends a speech command to the NVDA remote client.
func (c *NVDARemoteClient) SendRawSpeech(sequence []interface{}, args ...int) {
	// default priority is 0
	priority := 0
	if len(args) > 0 {
		priority = args[0]
	}
	// self.send(type="speak", sequence=sequence, priority=priority)
	c.Send(NewSpeakPacket(sequence, priority))
}

// SendSpeech sends a speech command to the NVDA remote client.
func (c *NVDARemoteClient) SendSpeech(text string, args ...int) {
	// default priority is 0
	priority := 0
	if len(args) > 0 {
		priority = args[0]
	}
	c.Send(NewSpeakPacket([]interface{}{text}, priority))
}

// CancelSpeech cancels the current speech.
func (c *NVDARemoteClient) CancelSpeech() {
	c.Send(NewCancelSpeechPacket())
}

// PauseSpeech pauses or resumes speech.
func (c *NVDARemoteClient) PauseSpeech(switchVal bool) {
	c.Send(NewPauseSpeechPacket(switchVal))
}

// SendBeep sends a beep command to the NVDA remote client.
func (c *NVDARemoteClient) SendBeep(hz float64, length int, left ...int) {
	leftVol := 50
	rightVol := 50

	if len(left) > 0 {
		leftVol = left[0]
	}

	if len(left) > 1 {
		rightVol = left[1]
	}
	c.Send(NewBeepPacket(hz, length, leftVol, rightVol))

}

// Wave sends a wave command to the NVDA remote client.
func (c *NVDARemoteClient) Wave(kwargs map[string]interface{}) {
	c.Send(NewWavePacket(kwargs))
}

// SendBraille sends braille data to the NVDA remote client.
func (c *NVDARemoteClient) SendBraille(data string) {
	c.Send(NewSendBraillePacket(data))
}

// SendRawKey sends a key event to the NVDA remote client.
func (c *NVDARemoteClient) SendRawKey(vkCode int, scanCode *int, extended *bool, pressed bool) {
	c.Send(NewKeyPacketRaw(vkCode, scanCode, extended, pressed))
}

// SendKey sends a key event to the NVDA remote client.
func (c *NVDARemoteClient) SendKey(key string, pressed bool) {
	// log the key event
	c.logger.Debug("Sending key event", "key", key, "pressed", pressed)
	keyPacket, err := NewKeyPacket(key, pressed)
	if err != nil {
		c.logger.Error("Error creating key packet", "error", err)
		c.errorChan <- err
		return
	}
	c.Send(keyPacket)
}

// TypeString types a string on the NVDA remote client.
func (c *NVDARemoteClient) TypeString(s string, delay int) {
	for _, r := range s {
		c.SendKey(string(r), true)
		time.Sleep(time.Duration(delay) * time.Millisecond)
		c.SendKey(string(r), false)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

}

func (c *NVDARemoteClient) sendKeystrokeHelper(key string, ctrl, shift, alt, win, insert bool) {
	// send all modifyers first
	if ctrl {
		c.SendKey("control", true)
	}
	if shift {
		c.SendKey("shift", true)
	}
	if alt {
		c.SendKey("alt", true)
	}
	if win {
		c.SendKey("leftWindows", true)
	}
	if insert {
		c.SendKey("insert", true)
	}
	// send the key
	c.SendKey(key, true)
	time.Sleep(50 * time.Millisecond)
	c.SendKey(key, false)
	// release all modifyers in reverse order
	if insert {
		c.SendKey("insert", false)
	}
	if win {
		c.SendKey("leftWindows", false)
	}
	if alt {
		c.SendKey("alt", false)
	}
	if shift {
		c.SendKey("shift", false)
	}
	if ctrl {
		c.SendKey("control", false)
	}
}

// SendKeystroke sends a keystroke to the NVDA remote client.
func (c *NVDARemoteClient) SendKeystroke(keystroke string) {
	// split by +
	parts := strings.Split(keystroke, "+")
	if len(parts) == 0 {
		return
	}
	key := parts[len(parts)-1]
	parts = parts[:len(parts)-1]
	ctrl := false
	shift := false
	alt := false
	win := false
	insert := false
	for _, part := range parts {
		switch part {
		case "control", "ctrl":
			ctrl = true
		case "shift":
			shift = true
		case "alt":
			alt = true
		case "windows", "win":
			win = true
		case "insert", "ins":
			insert = true
		default:
			c.logger.Warn("Unknown modifier", "modifier", part)
		} // end switch
	}
	c.sendKeystrokeHelper(key, ctrl, shift, alt, win, insert)
}
