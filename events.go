package nvda_remote_go

import (
	"encoding/json"
	"fmt"
)

type Event interface {
	Type() string
	String() string
}

type BaseEvent struct {
	EventType string `json:"type"`
}

func (b BaseEvent) String() string {
	return fmt.Sprintf("%s", b.EventType)
}

func (b BaseEvent) Type() string { return b.EventType }

// MOTDEvent is the event that is sent when the server sends a message of the day.
type MOTDEvent struct {
	BaseEvent
	Motd string `json:"motd"`
}

func (m MOTDEvent) String() string {
	return fmt.Sprintf("Message of the day: %s", m.Motd)
}

// NVRClient is the struct that contains information about the client that joined the channel.
type NVRClient struct {
	ID             int    `json:"id"`
	ConnectionType string `json:"connection_type"`
}

func (n NVRClient) String() string {
	return fmt.Sprintf("Client ID: %d, Connection Type: %s", n.ID, n.ConnectionType)
}

// ChannelJoinedEvent is the event that is sent when a client joins a channel.
type ChannelJoinedEvent struct {
	BaseEvent
	Channel string      `json:"channel"`
	ID      int         `json:"origin"`
	UserIDs []int       `json:"user_ids"`
	Clients []NVRClient `json:"clients"`
}

func (c ChannelJoinedEvent) String() string {
	return fmt.Sprintf("Channel joined: %s, ID: %d, Clients: %v", c.Channel, c.ID, c.Clients)
}

// ChannelLeftEvent is the event that is sent when a client leaves a channel.
// It is not sent when the client disconnects from the server.
type ChannelLeftEvent struct {
	BaseEvent
}

// ChannelMessageEvent is the event that is sent when a message is sent to a channel.
type ChannelMessageEvent struct {
	BaseEvent
	Message string `json:"message"`
	Origin  int    `json:"origin"`
}

func (c ChannelMessageEvent) String() string {
	return fmt.Sprintf("Channel message from %d: %s", c.Origin, c.Message)
}

// ClientJoinedEvent is the event that is sent when a client joins the server.
type ClientJoinedEvent struct {
	BaseEvent
	ID             int    `json:"client.id"`
	ConnectionType string `json:"client.connection_type"`
}

func (c ClientJoinedEvent) String() string {
	return fmt.Sprintf("a %s client with ID %d joined", c.ConnectionType, c.ID)
}

// ClientLeftEvent is the event that is sent when a client leaves the server.
type ClientLeftEvent struct {
	BaseEvent
	ID int `json:"origin"`
}

func (c ClientLeftEvent) String() string {
	return fmt.Sprintf("client with ID %d left", c.ID)
}

// SpeakEvent is the event that is sent when the server sends a speech command.
type SpeakEvent struct {
	BaseEvent
	Sequence []string `json:"sequence"`
	Priority int      `json:"priority"`
}

func (s SpeakEvent) String() string {
	return fmt.Sprintf("Speak event with sequence: %v, priority: %d", s.Sequence, s.Priority)
}

// CancelSpeechEvent is the event that is sent when the server sends a cancel speech command.
type CancelSpeechEvent struct {
	BaseEvent
}

func (c CancelSpeechEvent) String() string {
	return "Cancel speech event"
}

// PauseSpeechEvent is the event that is sent when the server sends a pause speech command.
type PauseSpeechEvent struct {
	BaseEvent
	Switch bool `json:"switch"`
}

func (p PauseSpeechEvent) String() string {
	if p.Switch {
		return "Pause speech event"
	} else {
		return "Resume speech event"
	}
}

// BeepEvent is the event that is sent when the server sends a beep command.
type BeepEvent struct {
	BaseEvent
	Hz     int `json:"hz"`
	Length int `json:"length"`
	Left   int `json:"left"`
	Right  int `json:"right"`
}

func (b BeepEvent) String() string {
	// hz and length are always present, left and right are optional
	if b.Left == 0 && b.Right == 0 {
		return fmt.Sprintf("Beep event with frequency %d Hz and length %d ms", b.Hz, b.Length)
	} else {
		return fmt.Sprintf("Beep event with frequency %d Hz, length %d ms, left volume %d, right volume %d", b.Hz, b.Length, b.Left, b.Right)
	}
}

// WaveEvent is the event that is sent when the server sends a wave command.
type WaveEvent struct {
	BaseEvent
	Kwargs map[string]interface{} `json:"-"`
}

func (w WaveEvent) String() string {
	// kwargs is a map of string to interface{}, so we need to convert it to a string
	// we can use json.Marshal to convert it to a string
	data, err := json.Marshal(w.Kwargs)
	if err != nil {
		return fmt.Sprintf("Wave event with error: %v", err)
	}
	return fmt.Sprintf("Wave event with kwargs: %s", data)
}

// SendBrailleEvent is the event that is sent when the server sends a braille command.
type SendBrailleEvent struct {
	BaseEvent
	Data interface{} `json:"data"`
}

func (s SendBrailleEvent) String() string {
	// data is a map of string to interface{}, so we need to convert it to a string
	// we can use json.Marshal to convert it to a string
	data, err := json.Marshal(s.Data)
	if err != nil {
		return fmt.Sprintf("Send braille event with error: %v", err)
	}
	return fmt.Sprintf("Send braille event with data: %s", data)
}

// KeyEvent is the event that is sent when the server sends a key command.
type KeyEvent struct {
	BaseEvent
	VKCode   int  `json:"vk_code"`
	ScanCode int  `json:"scan_code"`
	Extended bool `json:"extended"`
	Pressed  bool `json:"pressed"`
	Origin   int  `json:"origin"`
}

// GetKey returns key string from vk code and extended flag
func (k KeyEvent) GetKey() string {
	return GetKeyName(k.VKCode, k.ScanCode, k.Extended)
}

func (k KeyEvent) String() string {
	key := k.GetKey()
	if key == "" {
		return fmt.Sprintf("Key event with vk code %d, scan code %d, extended %t, pressed %t", k.VKCode, k.ScanCode, k.Extended, k.Pressed)
	}
	if k.Pressed {
		return fmt.Sprintf("Key event with key %s was pressed", key)
	} else {
		return fmt.Sprintf("Key event with key %s was released", key)
	}
}

// SetBrailleInfoEvent is the event that is sent when the server sends a braille info command.
type SetBrailleInfoEvent struct {
	BaseEvent
	Name     string `json:"name"`
	NumCells int    `json:"numCells"`
	Origin   int    `json:"origin"`
}

func (s SetBrailleInfoEvent) String() string {
	return fmt.Sprintf("Set braille info event: braille display name %s and number of cells %d", s.Name, s.NumCells)
}

type PingEvent struct {
	BaseEvent
}

func (p PingEvent) String() string {
	return "Ping event"
}

type InvalidEvent struct {
	BaseEvent
	RawData json.RawMessage
}

func (i InvalidEvent) String() string {
	return fmt.Sprintf("Invalid event: %s", i.RawData)
}

func ParseEvent(data []byte) (Event, error) {
	var base BaseEvent
	if err := json.Unmarshal(data, &base); err != nil {
		return InvalidEvent{RawData: data}, err
	}

	switch base.EventType {
	case "motd":
		var e MOTDEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "channel_joined":
		var e ChannelJoinedEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "channel_left":
		return ChannelLeftEvent{BaseEvent: base}, nil
	case "channel_message":
		var e ChannelMessageEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "client_joined":
		var e ClientJoinedEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "client_left":
		var e ClientLeftEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "speak":
		var e SpeakEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "cancel_speech":
		return CancelSpeechEvent{BaseEvent: base}, nil
	case "pause_speech":
		var e PauseSpeechEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "tone":
		var e BeepEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "wave":
		var e WaveEvent
		e.Kwargs = make(map[string]interface{})
		json.Unmarshal(data, &e.Kwargs)
		return e, nil
	case "braille":
		var e SendBrailleEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "key":
		var e KeyEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "set_braille_info":
		var e SetBrailleInfoEvent
		err := json.Unmarshal(data, &e)
		return e, err
	case "ping":
		return PingEvent{BaseEvent: base}, nil
	default:
		return InvalidEvent{
			BaseEvent: base,
			RawData:   data,
		}, fmt.Errorf("unknown event type: %s", base.EventType)
	}
}
