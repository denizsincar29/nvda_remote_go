package vgui

import (
	"fmt"
	"log/slog"
	"sync"
)

// GUIOption is a function that configures a GUI
type GUIOption func(*GUI)

// WithLocale sets the locale for the GUI
func WithLocale(locale Locale) GUIOption {
	return func(g *GUI) {
		g.localizer = NewLocalizer(locale)
	}
}

// WithLogger sets the logger for the GUI
func WithLogger(logger *slog.Logger) GUIOption {
	return func(g *GUI) {
		g.logger = logger
	}
}

// GUI represents a virtual GUI with multiple elements
type GUI struct {
	elements       []Element
	focusIndex     int
	mu             sync.RWMutex
	onSpeech       func(text string) // Callback to send speech output
	localizer      *Localizer
	logger         *slog.Logger
	defaultButton  *Button // The default button (activated by Enter)
	hotkeys        map[string]func() string // Hotkey map (e.g., "ctrl+s" -> callback)
	keyboardLayout *KeyboardLayoutManager
}

// NewGUI creates a new virtual GUI with optional configuration
func NewGUI(options ...GUIOption) *GUI {
	g := &GUI{
		elements:       make([]Element, 0),
		focusIndex:     -1,
		localizer:      NewLocalizer(LocaleEnglish), // Default to English
		logger:         slog.Default(),
		hotkeys:        make(map[string]func() string),
		keyboardLayout: NewKeyboardLayoutManager(LayoutUS), // Default to US layout
	}
	
	for _, option := range options {
		option(g)
	}
	
	return g
}

// AddElement adds an element to the GUI
func (g *GUI) AddElement(element Element) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	// Set localizer for elements that need it
	if localizableElem, ok := element.(LocalizableElement); ok {
		localizableElem.SetLocalizer(g.localizer)
	}
	
	g.elements = append(g.elements, element)
	
	// Set initial focus to first focusable element if not set
	if g.focusIndex == -1 && element.IsFocusable() {
		g.focusIndex = len(g.elements) - 1
	}
	
	// Track default button
	if btn, ok := element.(*Button); ok && btn.IsDefault {
		g.defaultButton = btn
	}
}

// SetSpeechCallback sets the callback function for speech output
func (g *GUI) SetSpeechCallback(callback func(text string)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onSpeech = callback
}

// speak sends speech output via the callback
func (g *GUI) speak(text string) {
	if g.onSpeech != nil {
		g.onSpeech(text)
	}
}

// GetFocusedElement returns the currently focused element
func (g *GUI) GetFocusedElement() Element {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	if g.focusIndex >= 0 && g.focusIndex < len(g.elements) {
		return g.elements[g.focusIndex]
	}
	return nil
}

// MoveFocusForward moves focus to the next focusable element (Tab key)
func (g *GUI) MoveFocusForward() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if len(g.elements) == 0 {
		return g.localizer.T("no elements")
	}
	
	startIndex := g.focusIndex
	for {
		g.focusIndex = (g.focusIndex + 1) % len(g.elements)
		
		if g.elements[g.focusIndex].IsFocusable() {
			elem := g.elements[g.focusIndex]
			g.logger.Debug("Focus moved forward", "element", elem.GetName())
			return elem.GetDescription()
		}
		
		// If we've looped back to the start, no focusable elements found
		if g.focusIndex == startIndex {
			return g.localizer.T("no focusable elements")
		}
	}
}

// MoveFocusBackward moves focus to the previous focusable element (Shift+Tab)
func (g *GUI) MoveFocusBackward() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if len(g.elements) == 0 {
		return g.localizer.T("no elements")
	}
	
	startIndex := g.focusIndex
	for {
		g.focusIndex--
		if g.focusIndex < 0 {
			g.focusIndex = len(g.elements) - 1
		}
		
		if g.elements[g.focusIndex].IsFocusable() {
			elem := g.elements[g.focusIndex]
			g.logger.Debug("Focus moved backward", "element", elem.GetName())
			return elem.GetDescription()
		}
		
		// If we've looped back to the start, no focusable elements found
		if g.focusIndex == startIndex {
			return g.localizer.T("no focusable elements")
		}
	}
}

// HandleKey processes a key press event and returns speech output
// This is a convenience method that delegates to HandleKeyWithModifiers with no modifiers
func (g *GUI) HandleKey(key string, pressed bool) string {
	return g.HandleKeyWithModifiers(key, []string{}, pressed)
}

// HandleKeyWithModifiers processes a key press event with modifiers and returns speech output
func (g *GUI) HandleKeyWithModifiers(key string, modifiers []string, pressed bool) string {
	// Only process key press (not release)
	if !pressed {
		return ""
	}
	
	// Check for hotkeys first
	hotkeyStr := buildHotkeyString(key, modifiers)
	g.mu.RLock()
	if callback, ok := g.hotkeys[hotkeyStr]; ok {
		g.mu.RUnlock()
		g.logger.Debug("Hotkey activated", "hotkey", hotkeyStr)
		return callback()
	}
	g.mu.RUnlock()
	
	g.mu.RLock()
	focusedElem := g.GetFocusedElement()
	g.mu.RUnlock()
	
	if focusedElem == nil {
		return ""
	}
	
	switch key {
	case "tab":
		return g.MoveFocusForward()
		
	case "enter":
		// If default button exists, activate it instead of focused element
		g.mu.RLock()
		defaultBtn := g.defaultButton
		g.mu.RUnlock()
		
		if defaultBtn != nil {
			g.logger.Debug("Activating default button", "button", defaultBtn.GetName())
			return defaultBtn.OnActivate()
		}
		g.logger.Debug("Activating focused element", "element", focusedElem.GetName())
		return focusedElem.OnActivate()
		
	case "space":
		// Space key behavior depends on element type
		if cb, ok := focusedElem.(*CheckBox); ok {
			return cb.Toggle()
		}
		return focusedElem.OnActivate()
		
	case "upArrow":
		// Handle listbox navigation
		if lb, ok := focusedElem.(*ListBox); ok {
			return lb.MoveUp()
		}
		// Handle textarea navigation
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.MoveUp()
		}
		
	case "downArrow":
		// Handle listbox navigation
		if lb, ok := focusedElem.(*ListBox); ok {
			return lb.MoveDown()
		}
		// Handle textarea navigation
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.MoveDown()
		}
		
	case "leftArrow":
		// Handle textbox navigation
		if tb, ok := focusedElem.(*TextBox); ok {
			if hasModifier(modifiers, "ctrl") {
				return tb.MoveToPreviousWord()
			}
			return tb.MoveLeft()
		}
		// Handle textarea navigation
		if ta, ok := focusedElem.(*TextArea); ok {
			if hasModifier(modifiers, "ctrl") {
				return ta.MoveToPreviousWord()
			}
			return ta.MoveLeft()
		}
		
	case "rightArrow":
		// Handle textbox navigation
		if tb, ok := focusedElem.(*TextBox); ok {
			if hasModifier(modifiers, "ctrl") {
				return tb.MoveToNextWord()
			}
			return tb.MoveRight()
		}
		// Handle textarea navigation
		if ta, ok := focusedElem.(*TextArea); ok {
			if hasModifier(modifiers, "ctrl") {
				return ta.MoveToNextWord()
			}
			return ta.MoveRight()
		}
		
	case "home":
		if tb, ok := focusedElem.(*TextBox); ok {
			return tb.MoveToStart()
		}
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.MoveToLineStart()
		}
		
	case "end":
		if tb, ok := focusedElem.(*TextBox); ok {
			return tb.MoveToEnd()
		}
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.MoveToLineEnd()
		}
		
	case "backspace":
		if tb, ok := focusedElem.(*TextBox); ok {
			return tb.DeleteCharBefore()
		}
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.DeleteCharBefore()
		}
		
	case "delete":
		if tb, ok := focusedElem.(*TextBox); ok {
			return tb.DeleteCharAfter()
		}
		if ta, ok := focusedElem.(*TextArea); ok {
			return ta.DeleteCharAfter()
		}
		
	case "a":
		// Ctrl+A: Select all
		if hasModifier(modifiers, "ctrl") {
			if tb, ok := focusedElem.(*TextBox); ok {
				return tb.SelectAll()
			}
			if ta, ok := focusedElem.(*TextArea); ok {
				return ta.SelectAll()
			}
		}
	}
	
	// Handle character input for text elements
	// Only accept character input if no modifiers (except Shift) are pressed
	if !hasModifier(modifiers, "ctrl") && !hasModifier(modifiers, "alt") {
		// Check if this key can be mapped to a character in the current layout
		shiftPressed := hasModifier(modifiers, "shift")
		if char, ok := g.keyboardLayout.GetCharForKey(key, shiftPressed); ok {
			if tb, ok := focusedElem.(*TextBox); ok {
				return tb.InsertChar(char)
			}
			if ta, ok := focusedElem.(*TextArea); ok {
				return ta.InsertChar(char)
			}
		}
	}
	
	return ""
}

// buildHotkeyString builds a hotkey string from key and modifiers
func buildHotkeyString(key string, modifiers []string) string {
	hotkeyStr := ""
	for _, mod := range modifiers {
		if mod == "ctrl" || mod == "control" {
			hotkeyStr += "ctrl+"
		}
		if mod == "shift" {
			hotkeyStr += "shift+"
		}
		if mod == "alt" {
			hotkeyStr += "alt+"
		}
	}
	hotkeyStr += key
	return hotkeyStr
}

// hasModifier checks if a modifier is present in the modifiers list
func hasModifier(modifiers []string, mod string) bool {
	for _, m := range modifiers {
		if m == mod || (mod == "ctrl" && m == "control") {
			return true
		}
	}
	return false
}

// SpeakFocusedElement speaks the currently focused element
func (g *GUI) SpeakFocusedElement() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	if g.focusIndex >= 0 && g.focusIndex < len(g.elements) {
		return g.elements[g.focusIndex].GetDescription()
	}
	return "No element focused"
}

// GetElementCount returns the number of elements in the GUI
func (g *GUI) GetElementCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.elements)
}

// GetElements returns all elements (for testing purposes)
func (g *GUI) GetElements() []Element {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	// Return a copy to prevent external modification
	elementsCopy := make([]Element, len(g.elements))
	copy(elementsCopy, g.elements)
	return elementsCopy
}

// Reset clears all elements and resets the GUI
func (g *GUI) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	g.elements = make([]Element, 0)
	g.focusIndex = -1
	g.defaultButton = nil
}

// RegisterHotkey registers a hotkey with a callback
func (g *GUI) RegisterHotkey(hotkey string, callback func() string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if _, exists := g.hotkeys[hotkey]; exists {
		return fmt.Errorf("hotkey %s already registered", hotkey)
	}
	
	g.hotkeys[hotkey] = callback
	g.logger.Debug("Hotkey registered", "hotkey", hotkey)
	return nil
}

// UnregisterHotkey removes a hotkey
func (g *GUI) UnregisterHotkey(hotkey string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	delete(g.hotkeys, hotkey)
	g.logger.Debug("Hotkey unregistered", "hotkey", hotkey)
}

// GetRegisteredHotkeys returns all registered hotkeys
func (g *GUI) GetRegisteredHotkeys() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	hotkeys := make([]string, 0, len(g.hotkeys))
	for hotkey := range g.hotkeys {
		hotkeys = append(hotkeys, hotkey)
	}
	return hotkeys
}

// SetDefaultButton sets the default button (activated by Enter key)
func (g *GUI) SetDefaultButton(button *Button) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	g.defaultButton = button
	button.IsDefault = true
}

// GetDefaultButton returns the default button
func (g *GUI) GetDefaultButton() *Button {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return g.defaultButton
}

// GetLocalizer returns the GUI's localizer
func (g *GUI) GetLocalizer() *Localizer {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return g.localizer
}

// SwitchKeyboardLayout switches to the next keyboard layout
func (g *GUI) SwitchKeyboardLayout() KeyboardLayout {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	return g.keyboardLayout.SwitchLayout()
}

// SetKeyboardLayout sets a specific keyboard layout
func (g *GUI) SetKeyboardLayout(layout KeyboardLayout) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	g.keyboardLayout.SetLayout(layout)
}

// GetKeyboardLayout returns the current keyboard layout
func (g *GUI) GetKeyboardLayout() KeyboardLayout {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return g.keyboardLayout.GetCurrentLayout()
}

// GetKeyboardLayoutName returns a human-readable name for a keyboard layout
func (g *GUI) GetKeyboardLayoutName(layout KeyboardLayout) string {
	return g.keyboardLayout.GetLayoutName(layout)
}

// String returns a string representation of the GUI
func (g *GUI) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return fmt.Sprintf("GUI with %d elements, focus at index %d", len(g.elements), g.focusIndex)
}
