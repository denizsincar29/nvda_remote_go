package nvda_remote_go

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
)

const DEFAULT_PORT = "6837"

type NVDARemoteClient struct {
	conn         *tls.Conn
	eventChan    chan Event
	sendChan     chan []byte
	errorChan    chan error
	closeChan    chan struct{}
	wg           sync.WaitGroup
	eventHandler func(Event)
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
		eventChan: make(chan Event, 100),
		sendChan:  make(chan []byte, 100),
		errorChan: make(chan error, 10),
		closeChan: make(chan struct{}),
		logger:    lgr,
	}

	client.wg.Add(2)
	go client.readLoop()
	go client.writeLoop()

	client.Send(map[string]interface{}{
		"type":    "protocol_version",
		"version": 2,
	})
	client.Send(map[string]interface{}{
		"type":            "join",
		"channel":         channel,
		"connection_type": connType,
	})

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
			event, err := ParseEvent(data)
			if err != nil {
				c.errorChan <- err
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

func (c *NVDARemoteClient) Send(data map[string]interface{}) error {
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

func (c *NVDARemoteClient) SetEventHandler(handler func(Event)) {
	c.eventHandler = handler
}

func (c *NVDARemoteClient) Events() <-chan Event {
	return c.eventChan
}

func (c *NVDARemoteClient) Errors() <-chan error {
	return c.errorChan
}

// SendSpeech sends a speech command to the NVDA remote client.
func (c *NVDARemoteClient) SendSpeech(sequence string, args ...int) {
	// default priority is 0
	priority := 0
	if len(args) > 0 {
		priority = args[0]
	}
	// self.send(type="speak", sequence=sequence, priority=priority)
	c.Send(map[string]interface{}{
		"type":     "speak",
		"sequence": sequence,
		"priority": priority,
	})
}

// CancelSpeech cancels the current speech.
func (c *NVDARemoteClient) CancelSpeech() {
	// self.send(type="cancel_speech")
	c.Send(map[string]interface{}{
		"type": "cancel_speech",
	})
}

// PauseSpeech pauses or resumes speech.
func (c *NVDARemoteClient) PauseSpeech(switchVal bool) {
	// self.send(type="pause_speech", switch=switch)
	c.Send(map[string]interface{}{
		"type":   "pause_speech",
		"switch": switchVal,
	})
}

// Beep sends a beep command to the NVDA remote client.
func (c *NVDARemoteClient) Beep(hz int, length int, left ...int) {
	leftVol := 50
	rightVol := 50

	if len(left) > 0 {
		leftVol = left[0]
	}

	if len(left) > 1 {
		rightVol = left[1]
	}

	// self.send(type="tone", hz=hz, length=length, left=left, right=right)
	c.Send(map[string]interface{}{
		"type":   "tone",
		"hz":     hz,
		"length": length,
		"left":   leftVol,
		"right":  rightVol,
	})
}

// Wave sends a wave command to the NVDA remote client.
func (c *NVDARemoteClient) Wave(kwargs map[string]interface{}) {
	// self.send(type="wave", kwargs=kwargs)
	c.Send(map[string]interface{}{
		"type":   "wave",
		"kwargs": kwargs,
	})
}

// SendBraille sends braille data to the NVDA remote client.
func (c *NVDARemoteClient) SendBraille(data string) {
	// self.send(type="braille", data=data)
	c.Send(map[string]interface{}{
		"type": "braille",
		"data": data,
	})
}
