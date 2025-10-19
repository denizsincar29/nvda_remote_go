package nvda_remote_go

import (
	"encoding/json"
	"fmt"

	"github.com/denizsincar29/nvda_remote_go/keys"
)

type Packet interface {
	Type() string
	String() string
}

type BasePacket struct {
	PacketType string `json:"type"`
}

func (b BasePacket) String() string {
	return fmt.Sprintf("type %s", b.PacketType)
}

func (b BasePacket) Type() string { return b.PacketType }

// MOTDPacket is the event that is sent when the server sends a message of the day.
type MOTDPacket struct {
	BasePacket
	Motd string `json:"motd"`
}

func (m MOTDPacket) String() string {
	return fmt.Sprintf("Message of the day: %s", m.Motd)
}

func NewMOTDPacket(motd string) MOTDPacket {
	return MOTDPacket{
		BasePacket: BasePacket{PacketType: "motd"},
		Motd:       motd,
	}
}

// NVRClient is the struct that contains information about the client that joined the channel.
type NVRClient struct {
	ID             int    `json:"id"`
	ConnectionType string `json:"connection_type"`
}

func (n NVRClient) String() string {
	return fmt.Sprintf("Client ID: %d, Connection Type: %s", n.ID, n.ConnectionType)
}

// ChannelJoinedPacket is the event that is sent when a client joins a channel.
// this is a server sent event
type ChannelJoinedPacket struct {
	BasePacket
	Channel string      `json:"channel"`
	ID      int         `json:"origin"`
	UserIDs []int       `json:"user_ids"`
	Clients []NVRClient `json:"clients"`
}

func (c ChannelJoinedPacket) String() string {
	return fmt.Sprintf("Channel joined: %s, ID: %d, Clients: %v", c.Channel, c.ID, c.Clients)
}

// ChannelLeftPacket is the event that is sent when a client leaves a channel.
// This is a server sent event.
type ChannelLeftPacket struct {
	BasePacket
}

// ChannelMessagePacket is the event that is sent when a message is sent to a channel.
// don't even know if it exists in the api.
type ChannelMessagePacket struct {
	BasePacket
	Message string `json:"message"`
	Origin  int    `json:"origin"`
}

func (c ChannelMessagePacket) String() string {
	return fmt.Sprintf("Channel message from %d: %s", c.Origin, c.Message)
}

func NewChannelMessagePacket(message string, origin int) ChannelMessagePacket {
	return ChannelMessagePacket{
		BasePacket: BasePacket{PacketType: "channel_message"},
		Message:    message,
		Origin:     origin,
	}
}

// ClientJoinedPacket is the event that is sent when a client joins the server.
// this is a server sent event
type ClientJoinedPacket struct {
	BasePacket
	ID             int    `json:"client.id"`
	ConnectionType string `json:"client.connection_type"`
}

func (c ClientJoinedPacket) String() string {
	return fmt.Sprintf("a %s client with ID %d joined", c.ConnectionType, c.ID)
}

// ClientLeftPacket is the event that is sent when a client leaves the server.
// this is a server sent event
type ClientLeftPacket struct {
	BasePacket
	ID int `json:"origin"`
}

func (c ClientLeftPacket) String() string {
	return fmt.Sprintf("client with ID %d left", c.ID)
}

// SpeakPacket is the event that is sent when the client sends a speech command.
// this event can be sent or received
type SpeakPacket struct {
	BasePacket
	Sequence []interface{} `json:"sequence"`
	Priority int           `json:"priority"`
	Origin   *int          `json:"origin,omitempty"`
}

func (s SpeakPacket) String() string {
	return fmt.Sprintf("Speak event with sequence: %v, priority: %d", s.GetSequence(), s.Priority)
}

// GetSequence returns the sequence of the speak event as a string.
func (s SpeakPacket) GetSequence() string {
	// get only the string values from the sequence, the others are special command arrays like ["character_mode", {"default": true, something: "something"}]
	// so we need to filter them out
	result := make([]string, 0)
	for _, item := range s.Sequence {
		switch v := item.(type) {
		case string:
			result = append(result, v)
		case map[string]interface{}:
			// do nothing, this is a special command array
		default:
			// do nothing, this is not a string or a map
		}
	}
	return fmt.Sprintf("%v", result)
}

func NewSpeakPacket(sequence []interface{}, priority int) SpeakPacket {
	return SpeakPacket{
		BasePacket: BasePacket{PacketType: "speak"},
		Sequence:   sequence,
		Priority:   priority,
		Origin:     nil,
	}
}

// CancelSpeechPacket is the event that is sent when the client sends a cancel speech command.
// this event can be sent or received
type CancelSpeechPacket struct {
	BasePacket
}

func (c CancelSpeechPacket) String() string {
	return "Cancel speech event"
}

func NewCancelSpeechPacket() CancelSpeechPacket {
	return CancelSpeechPacket{
		BasePacket: BasePacket{PacketType: "cancel_speech"},
	}
}

// CancelPacket is the event that is sent when the server sends a cancel command.
// This is something like a cancel speech command, but it is not clear what it does exactly.
type CancelPacket struct {
	BasePacket
}

func (c CancelPacket) String() string {
	return "Cancel event"
}

func NewCancelPacket() CancelPacket {
	return CancelPacket{
		BasePacket: BasePacket{PacketType: "cancel"},
	}
}

// PauseSpeechPacket is the event that is sent when the server sends a pause speech command.
type PauseSpeechPacket struct {
	BasePacket
	Switch bool `json:"switch"`
}

func (p PauseSpeechPacket) String() string {
	if p.Switch {
		return "Pause speech event"
	} else {
		return "Resume speech event"
	}
}

func NewPauseSpeechPacket(switchVal bool) PauseSpeechPacket {
	return PauseSpeechPacket{
		BasePacket: BasePacket{PacketType: "pause_speech"},
		Switch:     switchVal,
	}
}

// PauseSpeech is a function that returns a pause speech packet with true switch value.
func PauseSpeech() PauseSpeechPacket {
	return NewPauseSpeechPacket(true)
}

// ResumeSpeech is a function that returns a resume speech packet with false switch value.
func ResumeSpeech() PauseSpeechPacket {
	return NewPauseSpeechPacket(false)
}

// BeepPacket is the event that is sent when the server sends a beep command.
type BeepPacket struct {
	BasePacket
	Hz     float64 `json:"hz"`
	Length int     `json:"length"`
	Left   int     `json:"left"`
	Right  int     `json:"right"`
}

func (b BeepPacket) String() string {
	// hz and length are always present, left and right are optional
	if b.Left == 0 && b.Right == 0 {
		return fmt.Sprintf("Beep event with frequency %f Hz and length %d ms", b.Hz, b.Length)
	} else {
		return fmt.Sprintf("Beep event with frequency %f Hz, length %d ms, left volume %d, right volume %d", b.Hz, b.Length, b.Left, b.Right)
	}
}

func NewBeepPacket(hz float64, length int, args ...int) BeepPacket {
	left := 50
	right := 50
	if len(args) > 0 {
		left = args[0]
	}
	if len(args) > 1 {
		right = args[1]
	}
	return BeepPacket{
		BasePacket: BasePacket{PacketType: "tone"},
		Hz:         hz,
		Length:     length,
		Left:       left,
		Right:      right,
	}
}

// WavePacket is the event that is sent when the server sends a wave command.
// this event can be sent or received
type WavePacket struct {
	BasePacket
	Kwargs map[string]interface{} `json:"-"`
}

func (w WavePacket) String() string {
	// kwargs is a map of string to interface{}, so we need to convert it to a string
	// we can use json.Marshal to convert it to a string
	data, err := json.Marshal(w.Kwargs)
	if err != nil {
		return fmt.Sprintf("Wave event with error: %v", err)
	}
	return fmt.Sprintf("Wave event with kwargs: %s", data)
}

func NewWavePacket(kwargs map[string]interface{}) WavePacket {
	return WavePacket{
		BasePacket: BasePacket{PacketType: "wave"},
		Kwargs:     kwargs,
	}
}

// SendBraillePacket is the event that is sent when the client sends a braille command.
// this event can be sent or received
type SendBraillePacket struct {
	BasePacket
	Data interface{} `json:"data"`
}

func (s SendBraillePacket) String() string {
	// data is a map of string to interface{}, so we need to convert it to a string
	// we can use json.Marshal to convert it to a string
	data, err := json.Marshal(s.Data)
	if err != nil {
		return fmt.Sprintf("Send braille event with error: %v", err)
	}
	return fmt.Sprintf("Send braille event with data: %s", data)
}

func NewSendBraillePacket(data interface{}) SendBraillePacket {
	return SendBraillePacket{
		BasePacket: BasePacket{PacketType: "braille"},
		Data:       data,
	}
}

// KeyPacket is the event that is sent when the client sends a key event.
type KeyPacket struct {
	BasePacket
	VKCode   int   `json:"vk_code"`
	ScanCode *int  `json:"scan_code"`
	Extended *bool `json:"extended"`
	Pressed  bool  `json:"pressed"`
	Origin   *int  `json:"origin,omitempty"`
}

// GetKey returns key string from vk code and extended flag
func (k KeyPacket) GetKey() (string, error) {
	return keys.GetKeyName(k.VKCode, k.Extended)
}

func (k KeyPacket) String() string {
	key, err := k.GetKey()
	if key == "" || err != nil {
		return fmt.Sprintf("Key event with vk code %d, scan code %v, extended %v, pressed %t", k.VKCode, k.ScanCode, k.Extended, k.Pressed)
	}
	if k.Pressed {
		return fmt.Sprintf("Key event with key %s was pressed", key)
	} else {
		return fmt.Sprintf("Key event with key %s was released", key)
	}
}

func NewKeyPacketRaw(vkCode int, scanCode *int, extended *bool, pressed bool) KeyPacket {
	return KeyPacket{
		BasePacket: BasePacket{PacketType: "key"},
		VKCode:     vkCode,
		ScanCode:   scanCode,
		Extended:   extended,
		Pressed:    pressed,
		Origin:     nil,
	}
}

func NewKeyPacket(key string, pressed bool) (KeyPacket, error) {
	// if key is " ", convert it to "space"
	if key == " " {
		key = "space"
	}
	key_info, err := keys.GetKeyInfo(key)
	if err != nil {
		return KeyPacket{}, err
	}
	return NewKeyPacketRaw(key_info.VKCode, key_info.ScanCode, key_info.Extended, pressed), nil
}

// SetBrailleInfoPacket is the event that is sent when the server sends a braille info command.
type SetBrailleInfoPacket struct {
	BasePacket
	Name     string `json:"name"`
	NumCells int    `json:"numCells"`
	Origin   *int   `json:"origin,omitempty"`
}

func (s SetBrailleInfoPacket) String() string {
	return fmt.Sprintf("Set braille info event: braille display name %s and number of cells %d", s.Name, s.NumCells)
}

func NewSetBrailleInfoPacket(name string, numCells int) SetBrailleInfoPacket {
	return SetBrailleInfoPacket{
		BasePacket: BasePacket{PacketType: "set_braille_info"},
		Name:       name,
		NumCells:   numCells,
		Origin:     nil,
	}
}

// SetClipboardTextPacket is the event that is sent when the client sends a clipboard text command.
type SetClipboardTextPacket struct {
	BasePacket
	Text   string `json:"text"`
	Origin *int   `json:"origin,omitempty"`
}

func (s SetClipboardTextPacket) String() string {
	return fmt.Sprintf("Set clipboard text: %s", s.Text)
}

func NewSetClipboardTextPacket(text string) SetClipboardTextPacket {
	return SetClipboardTextPacket{
		BasePacket: BasePacket{PacketType: "set_clipboard_text"},
		Text:       text,
		Origin:     nil,
	}
}

// SendSAS is the event that is sent when the client sends send ctrl+alt+del command.
type SendSASPacket struct {
	BasePacket
	Origin *int `json:"origin,omitempty"`
}

func (s SendSASPacket) String() string {
	return "Send SAS event"
}

func NewSendSASPacket() SendSASPacket {
	return SendSASPacket{
		BasePacket: BasePacket{PacketType: "send_SAS"},
		Origin:     nil,
	}
}

// PingPacket is the event that is sent when the server sends a ping command.
// this event is only sent by the server to check if the client is still connected.
type PingPacket struct {
	BasePacket
}

func (p PingPacket) String() string {
	return "Ping event"
}

// NvdaNotConnectedPacket is the event indicating the remote computer on the other side is not connected
// this event is only sent by the server to indicate that the remote computer is not connected
type NvdaNotConnectedPacket struct {
	BasePacket
}

func (n NvdaNotConnectedPacket) String() string {
	return "nvda_not_connected event"
}

// HandShakePacket is the package that client sends to the server when it connects.
type HandShakePacket struct {
	BasePacket
	ProtocolVersion int `json:"version"`
}

func (h HandShakePacket) String() string {
	return fmt.Sprintf("Handshake event with protocol version %d", h.ProtocolVersion)
}

// SelfJoinPacket is the event that is sent when the client joins the channel.
type SelfJoinPacket struct {
	BasePacket
	Channel        string `json:"channel"`
	ConnectionType string `json:"connection_type"`
}

func (s SelfJoinPacket) String() string {
	return fmt.Sprintf("Self join event: channel %s, connection type %s", s.Channel, s.ConnectionType)
}

// NewJoinPackets returns both the handshake and self join packets.
// Protocol version is always 2, so we don't need to pass it as an argument.
func NewJoinPackets(channel string, connType string) (HandShakePacket, SelfJoinPacket) {
	handshake := HandShakePacket{
		BasePacket:      BasePacket{PacketType: "protocol_version"},
		ProtocolVersion: 2,
	}
	selfJoin := SelfJoinPacket{
		BasePacket:     BasePacket{PacketType: "join"},
		Channel:        channel,
		ConnectionType: connType,
	}
	return handshake, selfJoin
}

// InvalidPacket is the event that is sent when the server sends an invalid or unknown command.
type InvalidPacket struct {
	BasePacket
	RawData json.RawMessage
}

func (i InvalidPacket) String() string {
	return fmt.Sprintf("Invalid event: %s", i.RawData)
}

func ParsePacket(data []byte) (Packet, error) {
	var base BasePacket
	if err := json.Unmarshal(data, &base); err != nil {
		return InvalidPacket{RawData: data}, err
	}

	switch base.PacketType {
	case "motd":
		var e MOTDPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "channel_joined":
		var e ChannelJoinedPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "channel_left":
		return ChannelLeftPacket{BasePacket: base}, nil
	case "channel_message":
		var e ChannelMessagePacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "client_joined":
		var e ClientJoinedPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "client_left":
		var e ClientLeftPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "speak":
		var e SpeakPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "cancel_speech":
		return CancelSpeechPacket{BasePacket: base}, nil
	case "cancel":
		return CancelPacket{BasePacket: base}, nil
	case "pause_speech":
		var e PauseSpeechPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "tone":
		var e BeepPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "wave":
		var e WavePacket
		e.Kwargs = make(map[string]interface{})
		err := json.Unmarshal(data, &e.Kwargs)
		return e, err
	case "braille":
		var e SendBraillePacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "key":
		var e KeyPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "set_braille_info":
		var e SetBrailleInfoPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "set_clipboard_text":
		var e SetClipboardTextPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "send_SAS":
		var e SendSASPacket
		err := json.Unmarshal(data, &e)
		return e, err
	case "ping":
		return PingPacket{BasePacket: base}, nil
	case "nvda_not_connected":
		return NvdaNotConnectedPacket{BasePacket: base}, nil
	default:
		return InvalidPacket{
			BasePacket: base,
			RawData:    data,
		}, fmt.Errorf("unknown event type: %s", base.PacketType)
	}
}
