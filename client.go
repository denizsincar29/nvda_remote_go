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

// FingerprintManagerInterface defines the methods required for managing server certificate fingerprints.
// This abstraction allows for different storage backends (e.g., in-memory, disk) and facilitates mocking in tests.
type FingerprintManagerInterface interface {
	Get(hostPort string) (string, bool) // Get retrieves the known fingerprint for a host:port.
	Add(hostPort, fingerprint string) error // Add stores a fingerprint for a host:port.
	// TODO: Consider if Load() and Save() need to be part of an interface
	// if more complex mocking or alternative storage backends are envisioned.
	// For now, Get and Add are sufficient for NVDARemoteClient's direct usage.
}

// OperatingMode defines how the client handles server fingerprint verification,
// working in conjunction with the FingerprintManager.
type OperatingMode int

const (
	// ModeTOFU (Trust On First Use): On the first connection to a server, if its fingerprint is unknown,
	// the client will proceed with the connection (after CheckServer returns successfully with VerificationUnknown status)
	// and the application can then choose to Trust() the fingerprint, saving it via the FingerprintManager.
	// Subsequent connections will verify against this stored fingerprint. A mismatch will result in an error.
	ModeTOFU OperatingMode = iota
	// ModeStrict: The client will only allow connections if the server's fingerprint is already known
	// to the FingerprintManager and matches the presented fingerprint. It will not automatically
	// trust or allow proceeding with unknown fingerprints; CheckServer will fail in such cases.
	ModeStrict
)

// FingerprintError is an error type returned by the client's certificate verification logic
// (specifically from the VerifyPeerCertificate callback or CheckServer method)
// when an issue related to server fingerprint validation occurs.
type FingerprintError struct {
	// Status indicates the specific outcome of the fingerprint verification that led to this error.
	Status VerificationStatus
	// PresentedFingerprint is the fingerprint (SHA256 hex string) of the certificate presented by the server.
	PresentedFingerprint string
	// ExpectedFingerprint is the fingerprint (SHA256 hex string) that was expected, if one was known (e.g., from the FingerprintManager).
	ExpectedFingerprint string
	// IsStrict indicates whether this error occurred while the client was operating in ModeStrict.
	IsStrict bool
	// err wraps a more specific underlying error, e.g., from a direct comparison or a policy decision.
	err error
}

// Error returns a string representation of the FingerprintError.
func (fe *FingerprintError) Error() string {
	var msg string
	switch fe.Status {
	case VerificationMismatch:
		msg = fmt.Sprintf("server fingerprint mismatch: presented '%s', expected '%s'", fe.PresentedFingerprint, fe.ExpectedFingerprint)
	case VerificationUnknown:
		if fe.IsStrict {
			msg = fmt.Sprintf("server fingerprint '%s' is unknown and client is in strict mode", fe.PresentedFingerprint)
		} else {
			// This case should ideally not be an error in TOFU mode from VerifyPeerCertificate directly,
			// but can be set by CheckServer logic.
			msg = fmt.Sprintf("server fingerprint '%s' is unknown", fe.PresentedFingerprint)
		}
	default:
		msg = fmt.Sprintf("fingerprint verification error: status %v, presented '%s'", fe.Status, fe.PresentedFingerprint)
	}
	if fe.err != nil {
		return fmt.Sprintf("%s: %v", msg, fe.err)
	}
	return msg
}

// Unwrap returns the underlying error, if any.
func (fe *FingerprintError) Unwrap() error {
	return fe.err
}

const DEFAULT_PORT = "6837"

type NVDARemoteClient struct {
	// Configuration (set before CheckServer)
	host           string
	port           string
	channel        string
	connType       string
	logger         *slog.Logger
	fpManager      FingerprintManagerInterface // Interface for managing known server fingerprints.
	targetHostPort string // Combined host:port, used as a key for fingerprint management.
	opMode         OperatingMode               // Verification operating mode (TOFU or Strict), defaults to ModeTOFU.

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
// The client defaults to ModeTOFU for fingerprint verification.
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
		opMode:             ModeTOFU, // Default to TOFU mode
	}, nil
}

// CheckServer attempts a TLS connection to the server to perform two main validation steps:
// 1. Standard TLS Handshake and CA Validation: It performs a full TLS handshake.
//    Since `tls.Config.InsecureSkipVerify` is set to `false`, the Go crypto/tls library
//    will perform standard certificate validation, including checking against known Certificate Authorities (CAs),
//    verifying certificate expiry, and other standard checks. If this fails (e.g., the server uses
//    a self-signed certificate not known to the system's CA pool), the handshake will typically fail.
// 2. Fingerprint Pinning: Via the `VerifyPeerCertificate` callback, this method implements
//    fingerprint pinning as an additional security layer. The callback (`verifyPeerCertificateLogic`)
//    calculates the fingerprint of the server's presented certificate and compares it against
//    a stored fingerprint if one is known for that server (managed by `fpManager`), according
//    to the configured `opMode` (TOFU or Strict).
//
// Return Behavior:
// - A non-nil `error` from `CheckServer` indicates a failure in establishing a trusted connection.
//   This can be due to various reasons:
//     - Network errors (e.g., host unreachable).
//     - Standard CA validation failure (e.g., certificate signed by unknown authority, expired certificate).
//     - Certificate parsing errors encountered in the `VerifyPeerCertificate` callback.
//     - Fingerprint mismatch (if a known fingerprint exists and doesn't match the presented one).
//     - Unknown fingerprint when operating in `ModeStrict`.
//   When an error is returned, the client's state is typically `StateClosed`. The specific nature
//   of the failure can sometimes be inferred from `VerificationStatus()` or the error message itself.
//   If the error is a `*FingerprintError`, it directly indicates a fingerprint validation issue from our callback.
//   If it's a `*tls.CertificateVerificationError`, it indicates a failure in the standard CA/chain validation.
// - A `nil` error from `CheckServer` means the TLS handshake was successful AND the server's
//   fingerprint meets the criteria of the current `OperatingMode` to proceed.
//   After a `nil` error, the application should check `VerificationStatus()`:
//     - If `VerificationOK`: The server's fingerprint is known and matches (or was already trusted).
//       The client is in `StateTrusted`, and `Connect()` can be called to establish the application-level connection.
//     - If `VerificationUnknown` (this only occurs in `ModeTOFU`): The server's fingerprint was not previously known.
//       The client is in `StateChecked`. The application should retrieve the `ServerFingerprint()`,
//       present it to the user or check against an out-of-band source, and if deemed trustworthy,
//       call `Trust()` to store the fingerprint and move the client to `StateTrusted`. `Connect()` can then be called.
//
// This method populates `ServerFingerprint()` with the presented fingerprint (if parsable) and
// sets `VerificationStatus()` and `State()` according to the outcome. It does NOT start read/write loops.
func (c *NVDARemoteClient) CheckServer() error {
	if c.state != StateIdle {
		return fmt.Errorf("CheckServer can only be called in StateIdle (current: %v)", c.state)
	}
	c.logger.Debug("Checking server connection and fingerprint", "host", c.targetHostPort)
	c.verificationStatus = VerificationNotChecked
	c.serverFingerprint = "" // Clear previous fingerprint

	// certParseErr is a local variable to capture errors from certificate parsing within the callback.
	var certParseErr error

	conf := &tls.Config{
		ServerName: c.host,
		// InsecureSkipVerify is set to false to ensure standard CA validation is performed.
		// Our VerifyPeerCertificate callback then adds fingerprint pinning on top of that.
		// If a certificate is from an unknown CA but matches a pinned fingerprint (or is trusted via TOFU),
		// VerifyPeerCertificate returning nil signals that *our callback* doesn't see an issue.
		// However, the Go TLS handshake will still likely fail due to the CA validation error if the cert is self-signed.
		// If our callback returns an error (e.g. FingerprintError), that error should be returned by Handshake().
		InsecureSkipVerify: false,
		// Custom verification logic, executed after basic TLS checks (like chain validation if InsecureSkipVerify is false)
		// but before Handshake() returns.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// `certParseErr` is a closure variable from the CheckServer scope.
			// `verifyPeerCertificateLogic` will set it if a parsing error occurs.
			// It also sets c.serverFingerprint.
			// The error returned by verifyPeerCertificateLogic dictates the outcome of this callback.
			return c.verifyPeerCertificateLogic(rawCerts, verifiedChains, &certParseErr)
		},
	}

	// Attempt the dial
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", c.targetHostPort)
	if err != nil {
		c.logger.Error("TCP Dial failed", "host", c.targetHostPort, "error", err)
		c.state = StateClosed
		c.lastError = err
		c.verificationStatus = VerificationError // General error
		return err
	}

	// Perform TLS handshake
	conn := tls.Client(rawConn, conf)
	err = conn.Handshake()
	if err != nil {
		_ = rawConn.Close() // Close the underlying TCP conn if TLS fails
		c.state = StateClosed
    // c.lastError will be set below. The 'err' is the direct error from Handshake().
    // Log the presented fingerprint if the callback managed to set it.
    if c.serverFingerprint != "" {
        c.logger.Debug("Server fingerprint presented during (or just before) failed handshake", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
    } else {
        c.logger.Debug("Server fingerprint was NOT set by callback during (or just before) failed handshake", "host", c.targetHostPort)
    }


    // Prioritize parsing errors from our callback first, if certParseErr was set by it.
    if certParseErr != nil { // This is the certParseErr from CheckServer's scope, set by the callback
        c.lastError = certParseErr
        c.verificationStatus = VerificationError
        c.logger.Error("TLS Handshake failed: certificate parsing error from callback", "host", c.targetHostPort, "error", c.lastError)
        return c.lastError // Return the specific parsing error
    }

		var fe *FingerprintError
    if errors.As(err, &fe) { // Then check if the error from Handshake() is our FingerprintError
        c.lastError = err // The original error from Handshake() is fe
			c.verificationStatus = fe.Status
        // If it's a FingerprintError, c.serverFingerprint was definitely set by verifyPeerCertificateLogic.
        c.logger.Warn("TLS Handshake failed: FingerprintError from callback", "host", c.targetHostPort, "status", fe.Status, "presentedFingerprint", c.serverFingerprint, "isStrict", fe.IsStrict, "error", err)
    } else { // Otherwise, it's some other TLS error (e.g., CA validation, connection issue)
        c.lastError = err
        c.verificationStatus = VerificationError // Generic error for CA failure etc.
        c.logger.Error("TLS Handshake failed: general error", "host", c.targetHostPort, "error", err)
		}
    return c.lastError // Return the determined lastError
	}

	// Handshake succeeded
	c.conn = conn
	// c.serverFingerprint was set by verifyPeerCertificateLogic (via the callback)
	// Now, determine final verificationStatus and state based on post-handshake checks.

	// If InsecureSkipVerify is false, a standard verification error (like unknown authority)
	// might have occurred. If our verifyPeerCertificateLogic returned nil, it means we are
	// overriding that error (e.g. TOFU for a self-signed cert, or known-matching self-signed cert).
	// If verifyPeerCertificateLogic returned an error (e.g. mismatch), that error from the callback
	// should be the one returned by Handshake().

	// If handshake succeeded without any error (err == nil):
	// This means either:
	// 1. Standard CA validation passed AND our verifyPeerCertificateLogic passed (returned nil).
	// 2. Standard CA validation failed BUT our verifyPeerCertificateLogic overrode the error by returning nil.

	// The c.serverFingerprint is set by the callback.
	// The c.verificationStatus is NOT definitively set yet if handshake succeeded. It's set if handshake failed.
	// We need to determine it now based on fingerprint presence and opMode.

	expectedFp, known := c.fpManager.Get(c.targetHostPort)

	if c.serverFingerprint == "" && certParseErr == nil && !errors.As(err, new(*FingerprintError)) {
		// This case should ideally not be reached if certs were presented and parsed.
		// If serverFingerprint is empty but there was no parse error, it implies an issue.
		// However, certParseErr is handled by the handshake error block.
		// This block primarily focuses on fingerprint status post-successful handshake.
		 c.logger.Warn("CheckServer: Handshake apparently succeeded but server fingerprint is empty and no parsing error reported through callback.")
		 // Potentially treat as VerificationError unless specific conditions are met.
	}


	if !known {
		// Fingerprint is not in our store.
		if c.opMode == ModeStrict {
			// This should have been caught by verifyPeerCertificateLogic and failed the handshake.
			// If we reach here, it's an unexpected state.
			_ = c.conn.Close()
			c.state = StateClosed
			c.lastError = fmt.Errorf("internal error: handshake succeeded in Strict mode with unknown fingerprint '%s'", c.serverFingerprint)
			c.verificationStatus = VerificationError // Or VerificationUnknown, but this path implies an issue.
			c.logger.Error("CheckServer: Handshake succeeded in Strict mode but fingerprint is unknown (should have failed)", "fingerprint", c.serverFingerprint)
			return c.lastError
		}
		// TOFU mode, unknown fingerprint after successful handshake (CA might have been trusted, or self-signed overridden by nil from callback)
		c.verificationStatus = VerificationUnknown
		c.state = StateChecked // Ready for Trust()
		c.logger.Info("CheckServer: Handshake successful, server fingerprint is UNKNOWN (TOFU mode)", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	} else if !strings.EqualFold(expectedFp, c.serverFingerprint) {
		// Fingerprint is in store, but mismatches.
		// This should have been caught by verifyPeerCertificateLogic and failed the handshake.
		// If we reach here, it's an unexpected state.
		_ = c.conn.Close()
		c.state = StateClosed
		c.lastError = fmt.Errorf("internal error: handshake succeeded with mismatched fingerprint (presented: '%s', expected: '%s')", c.serverFingerprint, expectedFp)
		c.verificationStatus = VerificationMismatch
		c.logger.Error("CheckServer: Handshake succeeded but fingerprint mismatched (should have failed)", "presented", c.serverFingerprint, "expected", expectedFp)
		return c.lastError
	} else {
		// Known and matches.
		c.verificationStatus = VerificationOK
		c.state = StateTrusted
		c.logger.Info("CheckServer: Handshake successful, server fingerprint is TRUSTED", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	}
	return nil // Success
}

// verifyPeerCertificateLogic contains the core fingerprint checking logic.
// It's called by the VerifyPeerCertificate callback.
// The certParseErrPtr is a pointer to the certParseErr variable in CheckServer,
// allowing this function to signal a parsing failure that CheckServer can inspect.
func (c *NVDARemoteClient) verifyPeerCertificateLogic(rawCerts [][]byte, _ [][]*x509.Certificate, certParseErrPtr *error) error {
	if len(rawCerts) == 0 {
		c.serverFingerprint = "" // Ensure no misleading fingerprint
		*certParseErrPtr = errors.New("no peer certificates presented by server")
		c.logger.Error("verifyPeerCertificateLogic: No certificates presented", "host", c.targetHostPort)
		return *certParseErrPtr // This error will be returned by Handshake() if standard validation doesn't find another.
	}

	leafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		c.serverFingerprint = "" // Ensure no misleading fingerprint
		*certParseErrPtr = fmt.Errorf("failed to parse server's leaf certificate: %w", err)
		c.logger.Error("verifyPeerCertificateLogic: Failed to parse certificate", "host", c.targetHostPort, "error", err)
		return *certParseErrPtr // This error will be returned by Handshake()
	}

	// Set serverFingerprint as soon as it's calculated
	c.serverFingerprint = fingerprints.CalculateSha256Fingerprint(leafCert)
	c.logger.Debug("verifyPeerCertificateLogic: Calculated presented fingerprint", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)

	expectedFingerprint, known := c.fpManager.Get(c.targetHostPort)

	if !known {
		if c.opMode == ModeStrict {
			c.logger.Warn("verifyPeerCertificateLogic: Unknown fingerprint in Strict mode", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
			return &FingerprintError{
				Status:               VerificationUnknown,
				PresentedFingerprint: c.serverFingerprint,
				IsStrict:             true,
				err:                  errors.New("strict mode: unknown fingerprint"),
			}
		}
		// In TOFU mode, or if standard CA validation passed, an unknown fingerprint is okay here.
		// The final decision for TOFU unknown (if CA also failed) is handled by CheckServer's main logic post-handshake.
		// If CA passed, this is fine. If CA failed, returning nil here signals our callback "accepts" this cert for now.
		c.logger.Info("verifyPeerCertificateLogic: Unknown fingerprint", "host", c.targetHostPort, "fingerprint", c.serverFingerprint, "opMode", c.opMode)
		return nil
	}

	if !strings.EqualFold(expectedFingerprint, c.serverFingerprint) {
		c.logger.Warn("verifyPeerCertificateLogic: Fingerprint mismatch", "host", c.targetHostPort, "expected", expectedFingerprint, "got", c.serverFingerprint)
		return &FingerprintError{
			Status:               VerificationMismatch,
			PresentedFingerprint: c.serverFingerprint,
			ExpectedFingerprint:  expectedFingerprint,
			err:                  errors.New("fingerprint mismatch"),
		}
	}

	// Fingerprint is known and matches.
	c.logger.Info("verifyPeerCertificateLogic: Fingerprint OK (known and matches)", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	return nil
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

// Trust explicitly marks the server's most recently presented fingerprint (from a successful CheckServer call
// that resulted in VerificationUnknown) as trusted. It saves this fingerprint using the FingerprintManager
// for future connections and updates the client's state to StateTrusted.
//
// This method should typically only be called when:
// - `CheckServer()` has completed successfully (returned `nil`).
// - `client.State()` is `StateChecked`.
// - `client.VerificationStatus()` is `VerificationUnknown`.
// This specific state indicates that the client is in TOFU mode, encountered a new server fingerprint,
// and the application has decided to trust this new fingerprint.
func (c *NVDARemoteClient) Trust() error {
	if !(c.state == StateChecked && c.verificationStatus == VerificationUnknown) {
		errMsg := fmt.Sprintf("Trust() called in invalid state or status. State: %v, VerificationStatus: %v. Expected StateChecked and VerificationUnknown.", c.state, c.verificationStatus)
		c.logger.Error(errMsg)
		return errors.New(errMsg)
	}

	if c.serverFingerprint == "" {
		// This case should ideally be prevented by the state/status check above.
		err := errors.New("Trust() called but server fingerprint is missing, though state and status suggested it should be present")
		c.logger.Error("Trust: Server fingerprint missing unexpectedly", "error", err)
		c.lastError = err
		return err
	}

	c.logger.Info("Trusting server fingerprint", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	err := c.fpManager.Add(c.targetHostPort, c.serverFingerprint)
	if err != nil {
		c.logger.Error("Failed to save trusted fingerprint to manager", "host", c.targetHostPort, "fingerprint", c.serverFingerprint, "error", err)
		c.lastError = fmt.Errorf("failed to save trusted fingerprint: %w", err)
		// Do not change state to Trusted if save failed. Application might want to handle this.
		// The verificationStatus remains VerificationUnknown because the fingerprint is not yet trusted *by the manager*.
		return c.lastError
	}

	c.logger.Info("Fingerprint saved to manager. Marking client as trusted for this session.", "host", c.targetHostPort, "fingerprint", c.serverFingerprint)
	// Mark as trusted for this session
	c.state = StateTrusted
	c.verificationStatus = VerificationOK // Reflect that it's now considered OK for this session
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
