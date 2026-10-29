package vgui

import (
	"log/slog"
	"sync"

	"github.com/denizsincar29/nvda_remote_go"
)

// Remote is the part of the NVDA remote API the GUI needs. Both
// *nvda_remote_go.NVDARemoteClient and *nvda_remote_go.NVDARemoteServer
// satisfy it, so a virtual GUI works the same whether it is a client of a
// relay or the server the master connects to directly.
type Remote interface {
	SetEventHandler(func(nvda_remote_go.Packet))
	SendSpeech(text string, args ...int)
	CancelSpeech()
}

// HandlerOption configures a Handler.
type HandlerOption func(*Handler)

// WithExternalEvents tells the handler that its caller routes packets itself
// (for example a server that keeps one GUI per connected client). In that mode
// Start does not install a global event handler; feed the handler with
// HandlePacket instead.
func WithExternalEvents() HandlerOption {
	return func(h *Handler) { h.externalEvents = true }
}

// Handler manages the connection between a virtual GUI and an NVDA remote client
type Handler struct {
	client       Remote
	gui          *GUI
	logger       *slog.Logger
	mu           sync.RWMutex
	active       bool
	shiftPressed bool // Track shift key state for Shift+Tab
	ctrlPressed  bool // Track ctrl key state for Ctrl+key combinations
	altPressed   bool // Track alt key state for Alt+key combinations

	externalEvents bool
}

// NewHandler creates a new vgui handler for the given NVDA remote client
// The client MUST be in slave mode for the vgui to work properly
func NewHandler(client Remote, gui *GUI, logger *slog.Logger, opts ...HandlerOption) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	handler := &Handler{
		client: client,
		gui:    gui,
		logger: logger,
		active: false,
	}
	for _, opt := range opts {
		opt(handler)
	}

	// Set up speech callback
	gui.SetSpeechCallback(func(text string) {
		handler.speak(text)
	})

	return handler
}

// Start begins handling key events from the NVDA remote client
func (h *Handler) Start() {
	h.mu.Lock()
	h.active = true
	h.mu.Unlock()

	h.logger.Info("VGUI handler started")

	// Set event handler for the client unless the caller routes packets itself.
	if !h.externalEvents {
		h.client.SetEventHandler(func(packet nvda_remote_go.Packet) {
			h.handleEvent(packet)
		})
	}

	// Speak the initial focused element
	h.speak(h.gui.SpeakFocusedElement())
}

// speak interrupts the current announcement and says text. An empty text is a
// no-op, so callers can pass the result of a GUI method straight through.
func (h *Handler) speak(text string) {
	if text == "" {
		return
	}
	h.client.CancelSpeech()
	h.client.SendSpeech(text)
}

// Stop stops handling key events
func (h *Handler) Stop() {
	h.mu.Lock()
	h.active = false
	h.mu.Unlock()

	h.logger.Info("VGUI handler stopped")
}

// IsActive returns whether the handler is currently active
func (h *Handler) IsActive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.active
}

// HandlePacket feeds one packet into the GUI. Use it with WithExternalEvents
// when several GUIs share a single connection (one per server client).
func (h *Handler) HandlePacket(packet nvda_remote_go.Packet) {
	h.handleEvent(packet)
}

// handleEvent processes events from the NVDA remote client
func (h *Handler) handleEvent(packet nvda_remote_go.Packet) {
	h.mu.RLock()
	active := h.active
	h.mu.RUnlock()

	if !active {
		return
	}

	// We're primarily interested in key events
	switch event := packet.(type) {
	case nvda_remote_go.KeyPacket:
		h.handleKeyEvent(event)

	case nvda_remote_go.ClientJoinedPacket:
		h.logger.Info("Client joined", "id", event.ID, "type", event.ConnectionType)

	case nvda_remote_go.ClientLeftPacket:
		h.logger.Info("Client left", "id", event.ID)

	default:
		// Log other events if needed
		h.logger.Debug("Received event", "type", packet.Type())
	}
}

// handleKeyEvent processes key press events and updates the GUI
func (h *Handler) handleKeyEvent(event nvda_remote_go.KeyPacket) {
	key, err := event.GetKey()
	if err != nil {
		h.logger.Error("Failed to get key name", "error", err)
		return
	}

	h.logger.Debug("Key event", "key", key, "pressed", event.Pressed)

	// Track modifier key states
	if key == "shift" || key == "leftShift" || key == "rightShift" {
		h.mu.Lock()
		wasAltPressed := h.altPressed
		h.shiftPressed = event.Pressed
		h.mu.Unlock()

		// Check for Alt+Shift combination to switch keyboard layout
		if event.Pressed && wasAltPressed {
			newLayout := h.gui.SwitchKeyboardLayout()
			layoutName := h.gui.GetKeyboardLayoutName(newLayout)
			h.logger.Info("Keyboard layout switched", "layout", layoutName)
			h.speak("Layout: " + layoutName)
		}
		return // Don't process modifier key itself
	}

	if key == "control" || key == "leftControl" || key == "rightControl" {
		h.mu.Lock()
		h.ctrlPressed = event.Pressed
		h.mu.Unlock()
		return // Don't process modifier key itself
	}

	if key == "alt" || key == "leftAlt" || key == "rightAlt" {
		h.mu.Lock()
		wasShiftPressed := h.shiftPressed
		h.altPressed = event.Pressed
		h.mu.Unlock()

		// Check for Alt+Shift combination to switch keyboard layout
		if event.Pressed && wasShiftPressed {
			newLayout := h.gui.SwitchKeyboardLayout()
			layoutName := h.gui.GetKeyboardLayoutName(newLayout)
			h.logger.Info("Keyboard layout switched", "layout", layoutName)
			h.speak("Layout: " + layoutName)
		}
		return // Don't process modifier key itself
	}

	// Handle Shift+Tab for backward navigation
	if key == "tab" && event.Pressed {
		h.mu.RLock()
		shiftPressed := h.shiftPressed
		h.mu.RUnlock()

		if shiftPressed {
			// Shift+Tab: Move focus backward
			if speechText := h.gui.MoveFocusBackward(); speechText != "" {
				h.speak(speechText)
			}
			return
		}
	}

	// Build modifiers list
	h.mu.RLock()
	modifiers := []string{}
	if h.ctrlPressed {
		modifiers = append(modifiers, "ctrl")
	}
	if h.shiftPressed {
		modifiers = append(modifiers, "shift")
	}
	if h.altPressed {
		modifiers = append(modifiers, "alt")
	}
	h.mu.RUnlock()

	// Let the GUI handle the key with modifiers and get speech output
	if speechText := h.gui.HandleKeyWithModifiers(key, modifiers, event.Pressed); speechText != "" {
		h.speak(speechText)
	}
}

// GetGUI returns the GUI instance
func (h *Handler) GetGUI() *GUI {
	return h.gui
}

// GetRemote returns the remote this GUI is attached to (client or server).
func (h *Handler) GetRemote() Remote {
	return h.client
}
