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
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const DEFAULT_PORT = "6837"

type NVDARemoteClient struct {
	*packetSender
	conn         *tls.Conn
	eventChan    chan Packet
	sendChan     chan []byte
	errorChan    chan error
	closeChan    chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
	eventHandler func(Packet)
	logger       *slog.Logger
}

func NewClient(host, port, channel, connType string, lgr *slog.Logger) (*NVDARemoteClient, error) {
	if port == "" {
		port = DEFAULT_PORT
	}
	if lgr == nil {
		lgr = slog.Default()
	}
	lgr.Debug("Creating new NVDA remote client", "host", host, "port", port, "channel", channel, "connection_type", connType)
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), conf)
	if err != nil {
		return nil, err
	}

	client := &NVDARemoteClient{
		conn:      conn,
		eventChan: make(chan Packet, 1000),
		sendChan:  make(chan []byte, 100),
		errorChan: make(chan error, 10),
		closeChan: make(chan struct{}),
		wg:        sync.WaitGroup{},
		closeOnce: sync.Once{},
		logger:    lgr,
	}

	client.packetSender = newPacketSender(client.Send, lgr)

	client.wg.Add(2)
	go client.readLoop()
	go client.writeLoop()
	handshake, joinpacket := NewJoinPackets(channel, connType)
	client.logger.Debug("Sending handshake and join packet", "handshake", handshake, "joinpacket", joinpacket)
	client.Send(handshake)
	client.Send(joinpacket)

	return client, nil
}

// sendError reports an error without ever blocking the caller: a caller that
// does not read Errors() must not be able to freeze the read/write loops.
func (c *NVDARemoteClient) sendError(err error) {
	select {
	case c.errorChan <- err:
	default:
	}
}

// signalClose signals that the client is closing. It uses a sync.Once to ensure that the close channel is only closed once.
func (c *NVDARemoteClient) signalClose() {
	// sends to close channel only once
	c.closeOnce.Do(func() {
		close(c.closeChan)
	})
}

func (c *NVDARemoteClient) readLoop() {
	defer c.wg.Done()
	defer c.signalClose() // Signal that this goroutine is done

	tempBuffer := make([]byte, 1024) // Temporary buffer for reading
	buffer := make([]byte, 0, 16384) // Main buffer for storing data

	for {
		select {
		case <-c.closeChan:
			return
		default:
			c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // Reset deadline

			n, err := c.conn.Read(tempBuffer)
			if err != nil {
				if !strings.Contains(err.Error(), "timeout") {
					c.logger.Error("Error reading from connection", "error", err)
					c.sendError(err)
				}
				continue // or consider more drastic action if it's a fatal error
			}

			// Append to the main buffer
			buffer = append(buffer, tempBuffer[:n]...)

			for { // Process multiple packets in one read
				newLineIndex := strings.Index(string(buffer), "\n")
				if newLineIndex == -1 {
					break // No more complete packets
				}

				data := buffer[:newLineIndex]
				buffer = buffer[newLineIndex+1:]

				c.logger.Debug("Received data", "data", string(data))
				event, err := ParsePacket(data)
				if err != nil {
					c.sendError(err)
					continue
				}

				switch event.(type) {
				case PingPacket, *PingPacket:
					continue // keepalive, never surfaced to the user
				}

				if c.eventHandler != nil {
					c.eventHandler(event)
				} else {
					c.eventChan <- event
				}
			}
		}
	}
}

func (c *NVDARemoteClient) writeLoop() {
	defer c.wg.Done()
	defer c.signalClose() // Signal that this goroutine is done
	for {
		select {
		case <-c.closeChan:
			return
		case data := <-c.sendChan:
			_, err := c.conn.Write(append(data, '\n'))
			if err != nil {
				c.sendError(err)
				return
			}
		}
	}
}

func (c *NVDARemoteClient) Send(data Packet) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.sendChan <- jsonData
	return nil
}

func (c *NVDARemoteClient) Close() {
	c.logger.Debug("Closing NVDA remote client")
	c.signalClose() // Signal that the client is closing
	c.wg.Wait()
	c.conn.Close() // Close the connection now, after all goroutines are done
	close(c.eventChan)
	close(c.sendChan)
	close(c.errorChan)
}

func (c *NVDARemoteClient) SetEventHandler(handler func(Packet)) {
	c.eventHandler = handler
}

func (c *NVDARemoteClient) Events() <-chan Packet {
	return c.eventChan
}

func (c *NVDARemoteClient) Errors() <-chan error {
	return c.errorChan
}
