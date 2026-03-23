package vgui

import (
	"log/slog"
	"sync"

	"github.com/denizsincar29/nvda_remote_go"
)

// Handler manages the connection between a virtual GUI and an NVDA remote client
type Handler struct {
	client       *nvda_remote_go.NVDARemoteClient
	gui          *GUI
	logger       *slog.Logger
	mu           sync.RWMutex
	active       bool
	shiftPressed bool // Track shift key state for Shift+Tab
	ctrlPressed  bool // Track ctrl key state for Ctrl+key combinations
	altPressed   bool // Track alt key state for Alt+key combinations
}

// NewHandler creates a new vgui handler for the given NVDA remote client
// The client MUST be in slave mode for the vgui to work properly
func NewHandler(client *nvda_remote_go.NVDARemoteClient, gui *GUI, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	handler := &Handler{
		client: client,
		gui:    gui,
		logger: logger,
		active: false,
	}

	// Set up speech callback
	gui.SetSpeechCallback(func(text string) {
		if text != "" {
			// Cancel previous speech to ensure new speech interrupts
			client.CancelSpeech()
			logger.Debug("Cancelled previous speech before new announcement", "text", text)
			client.SendSpeech(text)
		}
	})

	return handler
}

// Start begins handling key events from the NVDA remote client
func (h *Handler) Start() {
	h.mu.Lock()
	h.active = true
	h.mu.Unlock()

	h.logger.Info("VGUI handler started")

	// Set event handler for the client
	h.client.SetEventHandler(func(packet nvda_remote_go.Packet) {
		h.handleEvent(packet)
	})

	// Speak the initial focused element
	if initialText := h.gui.SpeakFocusedElement(); initialText != "" {
		// Cancel any previous speech before initial announcement
		h.client.CancelSpeech()
		h.client.SendSpeech(initialText)
	}
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
			h.client.CancelSpeech()
			h.client.SendSpeech("Layout: " + layoutName)
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
			h.client.CancelSpeech()
			h.client.SendSpeech("Layout: " + layoutName)
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
				h.client.CancelSpeech()
				h.client.SendSpeech(speechText)
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
		h.client.CancelSpeech()
		h.client.SendSpeech(speechText)
	}
}

// GetGUI returns the GUI instance
func (h *Handler) GetGUI() *GUI {
	return h.gui
}

// GetClient returns the NVDA remote client instance
func (h *Handler) GetClient() *nvda_remote_go.NVDARemoteClient {
	return h.client
}
