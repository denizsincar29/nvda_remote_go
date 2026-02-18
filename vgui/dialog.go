package vgui

import (
	"log/slog"
)

// DialogConfig configures which standard buttons to create for a dialog
type DialogConfig struct {
	HasOK     bool
	HasCancel bool
	HasYes    bool
	HasNo     bool
}

// Dialog represents a dialog that wraps a GUI with standard buttons
type Dialog struct {
	*GUI
	config       DialogConfig
	OnResult     func(result string) string
	okButton     *Button
	cancelButton *Button
	yesButton    *Button
	noButton     *Button
	result       string
}

// NewDialog creates a new dialog with the given configuration
func NewDialog(config DialogConfig, options ...GUIOption) *Dialog {
	gui := NewGUI(options...)
	
	dialog := &Dialog{
		GUI:    gui,
		config: config,
	}
	
	// Create standard buttons based on config
	if config.HasOK {
		dialog.okButton = NewButton(gui.localizer.T("ok"))
		dialog.okButton.IsDefault = true
		dialog.okButton.OnClick = func() string {
			dialog.result = "ok"
			if dialog.OnResult != nil {
				return dialog.OnResult("ok")
			}
			return gui.localizer.T("ok")
		}
	}
	
	if config.HasYes {
		dialog.yesButton = NewButton(gui.localizer.T("yes"))
		dialog.yesButton.IsDefault = true
		dialog.yesButton.OnClick = func() string {
			dialog.result = "yes"
			if dialog.OnResult != nil {
				return dialog.OnResult("yes")
			}
			return gui.localizer.T("yes")
		}
	}
	
	if config.HasNo {
		dialog.noButton = NewButton(gui.localizer.T("no"))
		dialog.noButton.OnClick = func() string {
			dialog.result = "no"
			if dialog.OnResult != nil {
				return dialog.OnResult("no")
			}
			return gui.localizer.T("no")
		}
	}
	
	if config.HasCancel {
		dialog.cancelButton = NewButton(gui.localizer.T("cancel"))
		dialog.cancelButton.OnClick = func() string {
			dialog.result = "cancel"
			if dialog.OnResult != nil {
				return dialog.OnResult("cancel")
			}
			return gui.localizer.T("cancel")
		}
	}
	
	return dialog
}

// AddStandardButtons adds the standard buttons to the dialog
// This should be called after adding all custom elements
func (d *Dialog) AddStandardButtons() {
	if d.yesButton != nil {
		d.GUI.AddElement(d.yesButton)
	}
	
	if d.noButton != nil {
		d.GUI.AddElement(d.noButton)
	}
	
	if d.okButton != nil {
		d.GUI.AddElement(d.okButton)
	}
	
	if d.cancelButton != nil {
		d.GUI.AddElement(d.cancelButton)
	}
}

// HandleKey overrides GUI's HandleKey to add Escape key support
func (d *Dialog) HandleKey(key string, pressed bool) string {
	return d.HandleKeyWithModifiers(key, []string{}, pressed)
}

// HandleKeyWithModifiers overrides GUI's HandleKeyWithModifiers to add Escape key support
func (d *Dialog) HandleKeyWithModifiers(key string, modifiers []string, pressed bool) string {
	if !pressed {
		return ""
	}
	
	// Handle Escape key
	if key == "escape" && d.cancelButton != nil {
		d.GUI.logger.Debug("Escape key pressed, activating cancel button")
		return d.cancelButton.OnActivate()
	}
	
	// Delegate to GUI
	return d.GUI.HandleKeyWithModifiers(key, modifiers, pressed)
}

// GetResult returns the dialog result
func (d *Dialog) GetResult() string {
	return d.result
}

// NewConfirmDialog creates a Yes/No confirmation dialog
func NewConfirmDialog(message string, options ...GUIOption) *Dialog {
	config := DialogConfig{
		HasYes: true,
		HasNo:  true,
	}
	
	dialog := NewDialog(config, options...)
	
	// Add message label
	dialog.AddElement(NewLabel(message))
	
	// Add standard buttons
	dialog.AddStandardButtons()
	
	return dialog
}

// ConfirmDialogResult represents the result of a confirmation dialog
type ConfirmDialogResult struct {
	Confirmed bool
	Message   string
}

// SetConfirmCallback sets a callback that returns a boolean result
func (d *Dialog) SetConfirmCallback(callback func(confirmed bool) string) {
	d.OnResult = func(result string) string {
		confirmed := result == "yes"
		return callback(confirmed)
	}
}

// WindowManager manages multiple GUI windows
type WindowManager struct {
	windows      map[string]*GUI
	activeWindow string
	windowStack  []string
	logger       *slog.Logger
}

// NewWindowManager creates a new window manager
func NewWindowManager(logger *slog.Logger) *WindowManager {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &WindowManager{
		windows:     make(map[string]*GUI),
		windowStack: make([]string, 0),
		logger:      logger,
	}
}

// AddWindow adds a window to the manager
func (w *WindowManager) AddWindow(name string, gui *GUI) {
	w.windows[name] = gui
	
	// If no active window, make this the active one
	if w.activeWindow == "" {
		w.activeWindow = name
		w.windowStack = append(w.windowStack, name)
	}
	
	w.logger.Debug("Window added", "name", name)
}

// ShowModal shows a window as a modal dialog
func (w *WindowManager) ShowModal(name string, gui *GUI) {
	w.windows[name] = gui
	w.activeWindow = name
	w.windowStack = append(w.windowStack, name)
	
	w.logger.Debug("Modal window shown", "name", name)
}

// CloseWindow closes a window and returns to the previous one
func (w *WindowManager) CloseWindow(name string) {
	delete(w.windows, name)
	
	// Remove from stack
	for i, wname := range w.windowStack {
		if wname == name {
			w.windowStack = append(w.windowStack[:i], w.windowStack[i+1:]...)
			break
		}
	}
	
	// Update active window
	if w.activeWindow == name {
		if len(w.windowStack) > 0 {
			w.activeWindow = w.windowStack[len(w.windowStack)-1]
		} else {
			w.activeWindow = ""
		}
	}
	
	w.logger.Debug("Window closed", "name", name)
}

// GetActiveWindow returns the active window
func (w *WindowManager) GetActiveWindow() *GUI {
	if w.activeWindow == "" {
		return nil
	}
	return w.windows[w.activeWindow]
}

// GetWindow returns a window by name
func (w *WindowManager) GetWindow(name string) *GUI {
	return w.windows[name]
}

// HandleKey routes key events to the active window
func (w *WindowManager) HandleKey(key string, pressed bool) string {
	activeGUI := w.GetActiveWindow()
	if activeGUI == nil {
		return ""
	}
	
	return activeGUI.HandleKey(key, pressed)
}

// HandleKeyWithModifiers routes key events with modifiers to the active window
func (w *WindowManager) HandleKeyWithModifiers(key string, modifiers []string, pressed bool) string {
	activeGUI := w.GetActiveWindow()
	if activeGUI == nil {
		return ""
	}
	
	return activeGUI.HandleKeyWithModifiers(key, modifiers, pressed)
}
