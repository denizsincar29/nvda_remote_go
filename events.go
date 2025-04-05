package nvda_remote_go

import (
	"encoding/json"
	"fmt"
)

type Event interface {
	Type() string
}

type BaseEvent struct {
	EventType string `json:"type"`
}

func (b BaseEvent) Type() string { return b.EventType }

type MOTDEvent struct {
	BaseEvent
	Motd string `json:"motd"`
}

type ChannelJoinedEvent struct {
	BaseEvent
	ID int `json:"origin"`
}

type ChannelLeftEvent struct {
	BaseEvent
}

type ChannelMessageEvent struct {
	BaseEvent
	Message string `json:"message"`
	Origin  int    `json:"origin"`
}

type ClientJoinedEvent struct {
	BaseEvent
	ID             int    `json:"client.id"`
	ConnectionType string `json:"client.connection_type"`
}

type ClientLeftEvent struct {
	BaseEvent
	ID int `json:"origin"`
}

type SpeakEvent struct {
	BaseEvent
	Sequence []string `json:"sequence"`
	Priority int      `json:"priority"`
}

type CancelSpeechEvent struct {
	BaseEvent
}

type PauseSpeechEvent struct {
	BaseEvent
	Switch bool `json:"switch"`
}

type BeepEvent struct {
	BaseEvent
	Hz     int `json:"hz"`
	Length int `json:"length"`
	Left   int `json:"left"`
	Right  int `json:"right"`
}

type WaveEvent struct {
	BaseEvent
	Kwargs map[string]interface{} `json:"-"`
}

type SendBrailleEvent struct {
	BaseEvent
	Data interface{} `json:"data"`
}

type KeyEvent struct {
	BaseEvent
	VKCode   int  `json:"vk_code"`
	ScanCode int  `json:"scan_code"`
	Extended bool `json:"extended"`
	Pressed  bool `json:"pressed"`
	Origin   int  `json:"origin"`
}

type SetBrailleInfoEvent struct {
	BaseEvent
	Name     string `json:"name"`
	NumCells int    `json:"numCells"`
	Origin   int    `json:"origin"`
}

type PingEvent struct {
	BaseEvent
}

type InvalidEvent struct {
	BaseEvent
	RawData json.RawMessage
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
