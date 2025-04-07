package nvda_remote_go

import (
	"bufio"
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
	conn         *tls.Conn
	eventChan    chan Packet
	sendChan     chan []byte
	errorChan    chan error
	closeChan    chan struct{}
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
		errorChan: make(chan error),
		closeChan: make(chan struct{}),
		logger:    lgr,
	}

	client.wg.Add(2)
	go client.readLoop()
	go client.writeLoop()
	handshake, joinpacket := NewJoinPackets(channel, connType)
	client.logger.Debug("Sending handshake and join packet", "handshake", handshake, "joinpacket", joinpacket)
	client.Send(handshake)
	client.Send(joinpacket)

	return client, nil
}

func (c *NVDARemoteClient) readLoop() {
	defer c.wg.Done()
	reader := bufio.NewReader(c.conn)

	for {
		select {
		case <-c.closeChan:
			return
		default:
			data, err := reader.ReadBytes('\n')
			if err != nil {
				c.errorChan <- err
				return
			}
			// debug log
			c.logger.Debug("Received data", "data", string(data))
			event, err := ParsePacket(data)
			if err != nil {
				c.errorChan <- err
				continue
			}
			// if it's a ping event, don't send it to the event channel
			if _, ok := event.(*PingPacket); ok {
				continue
			}
			if c.eventHandler != nil {
				c.eventHandler(event)
			} else {
				c.eventChan <- event
			}
		}
	}
}

func (c *NVDARemoteClient) writeLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.closeChan:
			return
		case data := <-c.sendChan:
			_, err := c.conn.Write(append(data, '\n'))
			if err != nil {
				c.errorChan <- err
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
	close(c.closeChan)
	c.conn.Close()
	c.wg.Wait()
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
