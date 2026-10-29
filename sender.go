package nvda_remote_go

import (
	"log/slog"
	"strings"
	"time"
)

// packetSender holds the high level helpers (speech, beep, keys, braille and
// so on) shared by the client and the server. Both embed it, so the helper
// method set is identical no matter which side of the protocol you are on.
type packetSender struct {
	send   func(Packet) error
	logger *slog.Logger
}

func newPacketSender(send func(Packet) error, lgr *slog.Logger) *packetSender {
	if lgr == nil {
		lgr = slog.Default()
	}
	return &packetSender{send: send, logger: lgr}
}

// SendSpeech sends a speech command to the NVDA remote client.
func (p *packetSender) SendRawSpeech(sequence []interface{}, args ...int) {
	// default priority is 0
	priority := 0
	if len(args) > 0 {
		priority = args[0]
	}
	// self.send(type="speak", sequence=sequence, priority=priority)
	_ = p.send(NewSpeakPacket(sequence, priority))
}

// SendSpeech sends a speech command to the NVDA remote client.
func (p *packetSender) SendSpeech(text string, args ...int) {
	// default priority is 0
	priority := 0
	if len(args) > 0 {
		priority = args[0]
	}
	_ = p.send(NewSpeakPacket([]interface{}{text}, priority))
}

// CancelSpeech cancels the current speech.
func (p *packetSender) CancelSpeech() {
	_ = p.send(NewCancelSpeechPacket())
}

// PauseSpeech pauses or resumes speech.
func (p *packetSender) PauseSpeech(switchVal bool) {
	_ = p.send(NewPauseSpeechPacket(switchVal))
}

// SendBeep sends a beep command to the NVDA remote client.
func (p *packetSender) SendBeep(hz float64, length int, left ...int) {
	leftVol := 50
	rightVol := 50

	if len(left) > 0 {
		leftVol = left[0]
	}

	if len(left) > 1 {
		rightVol = left[1]
	}
	_ = p.send(NewBeepPacket(hz, length, leftVol, rightVol))
}

// Wave sends a wave command to the NVDA remote client.
func (p *packetSender) Wave(kwargs map[string]interface{}) {
	_ = p.send(NewWavePacket(kwargs))
}

// SendBraille sends braille data to the NVDA remote client.
func (p *packetSender) SendBraille(data string) {
	_ = p.send(NewSendBraillePacket(data))
}

// SendRawKey sends a key event to the NVDA remote client.
func (p *packetSender) SendRawKey(vkCode int, scanCode *int, extended *bool, pressed bool) {
	_ = p.send(NewKeyPacketRaw(vkCode, scanCode, extended, pressed))
}

// SendKey sends a key event to the NVDA remote client.
func (p *packetSender) SendKey(key string, pressed bool) {
	// log the key event
	p.logger.Debug("Sending key event", "key", key, "pressed", pressed)
	keyPacket, err := NewKeyPacket(key, pressed)
	if err != nil {
		p.logger.Error("Error creating key packet", "error", err)
		return
	}
	_ = p.send(keyPacket)
}

// TypeString types a string on the NVDA remote client.
func (p *packetSender) TypeString(s string, delay int) {
	for _, r := range s {
		p.SendKey(string(r), true)
		time.Sleep(time.Duration(delay) * time.Millisecond)
		p.SendKey(string(r), false)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

func (p *packetSender) sendKeystrokeHelper(key string, ctrl, shift, alt, win, insert bool) {
	// send all modifyers first
	if ctrl {
		p.SendKey("control", true)
	}
	if shift {
		p.SendKey("shift", true)
	}
	if alt {
		p.SendKey("alt", true)
	}
	if win {
		p.SendKey("leftWindows", true)
	}
	if insert {
		p.SendKey("insert", true)
	}
	// send the key
	p.SendKey(key, true)
	time.Sleep(50 * time.Millisecond)
	p.SendKey(key, false)
	// release all modifyers in reverse order
	if insert {
		p.SendKey("insert", false)
	}
	if win {
		p.SendKey("leftWindows", false)
	}
	if alt {
		p.SendKey("alt", false)
	}
	if shift {
		p.SendKey("shift", false)
	}
	if ctrl {
		p.SendKey("control", false)
	}
}

// SendKeystroke sends a keystroke to the NVDA remote client.
func (p *packetSender) SendKeystroke(keystroke string) {
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
			p.logger.Warn("Unknown modifier", "modifier", part)
		} // end switch
	}
	p.sendKeystrokeHelper(key, ctrl, shift, alt, win, insert)
}
