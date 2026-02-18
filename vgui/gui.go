package vgui

import (
	"fmt"
	"sync"
)

// GUI represents a virtual GUI with multiple elements
type GUI struct {
	elements   []Element
	focusIndex int
	mu         sync.RWMutex
	onSpeech   func(text string) // Callback to send speech output
}

// NewGUI creates a new virtual GUI
func NewGUI() *GUI {
	return &GUI{
		elements:   make([]Element, 0),
		focusIndex: -1,
	}
}

// AddElement adds an element to the GUI
func (g *GUI) AddElement(element Element) {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	g.elements = append(g.elements, element)
	
	// Set initial focus to first focusable element if not set
	if g.focusIndex == -1 && element.IsFocusable() {
		g.focusIndex = len(g.elements) - 1
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
		return "No elements"
	}
	
	startIndex := g.focusIndex
	for {
		g.focusIndex = (g.focusIndex + 1) % len(g.elements)
		
		if g.elements[g.focusIndex].IsFocusable() {
			elem := g.elements[g.focusIndex]
			return elem.GetDescription()
		}
		
		// If we've looped back to the start, no focusable elements found
		if g.focusIndex == startIndex {
			return "No focusable elements"
		}
	}
}

// MoveFocusBackward moves focus to the previous focusable element (Shift+Tab)
func (g *GUI) MoveFocusBackward() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	
	if len(g.elements) == 0 {
		return "No elements"
	}
	
	startIndex := g.focusIndex
	for {
		g.focusIndex--
		if g.focusIndex < 0 {
			g.focusIndex = len(g.elements) - 1
		}
		
		if g.elements[g.focusIndex].IsFocusable() {
			elem := g.elements[g.focusIndex]
			return elem.GetDescription()
		}
		
		// If we've looped back to the start, no focusable elements found
		if g.focusIndex == startIndex {
			return "No focusable elements"
		}
	}
}

// HandleKey processes a key press event and returns speech output
func (g *GUI) HandleKey(key string, pressed bool) string {
	// Only process key press (not release)
	if !pressed {
		return ""
	}
	
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
		
	case "downArrow":
		// Handle listbox navigation
		if lb, ok := focusedElem.(*ListBox); ok {
			return lb.MoveDown()
		}
	}
	
	return ""
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
}

// String returns a string representation of the GUI
func (g *GUI) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	
	return fmt.Sprintf("GUI with %d elements, focus at index %d", len(g.elements), g.focusIndex)
}
