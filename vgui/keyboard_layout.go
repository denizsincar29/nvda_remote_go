package vgui

import "sync"

// KeyboardLayout represents a keyboard layout name
type KeyboardLayout string

const (
	LayoutUS      KeyboardLayout = "us"
	LayoutRussian KeyboardLayout = "ru"
	LayoutGerman  KeyboardLayout = "de"
)

// KeyboardLayoutManager handles keyboard layout mappings
type KeyboardLayoutManager struct {
	currentLayout KeyboardLayout
	layouts       map[KeyboardLayout]map[string]map[bool]rune // layout -> key -> shift state -> character
	mu            sync.RWMutex
}

// NewKeyboardLayoutManager creates a new keyboard layout manager
func NewKeyboardLayoutManager(initialLayout KeyboardLayout) *KeyboardLayoutManager {
	klm := &KeyboardLayoutManager{
		currentLayout: initialLayout,
		layouts:       make(map[KeyboardLayout]map[string]map[bool]rune),
	}
	klm.initializeLayouts()
	return klm
}

// initializeLayouts initializes keyboard layout mappings
func (klm *KeyboardLayoutManager) initializeLayouts() {
	// US English layout
	klm.layouts[LayoutUS] = map[string]map[bool]rune{
		// Letters
		"a": {false: 'a', true: 'A'},
		"b": {false: 'b', true: 'B'},
		"c": {false: 'c', true: 'C'},
		"d": {false: 'd', true: 'D'},
		"e": {false: 'e', true: 'E'},
		"f": {false: 'f', true: 'F'},
		"g": {false: 'g', true: 'G'},
		"h": {false: 'h', true: 'H'},
		"i": {false: 'i', true: 'I'},
		"j": {false: 'j', true: 'J'},
		"k": {false: 'k', true: 'K'},
		"l": {false: 'l', true: 'L'},
		"m": {false: 'm', true: 'M'},
		"n": {false: 'n', true: 'N'},
		"o": {false: 'o', true: 'O'},
		"p": {false: 'p', true: 'P'},
		"q": {false: 'q', true: 'Q'},
		"r": {false: 'r', true: 'R'},
		"s": {false: 's', true: 'S'},
		"t": {false: 't', true: 'T'},
		"u": {false: 'u', true: 'U'},
		"v": {false: 'v', true: 'V'},
		"w": {false: 'w', true: 'W'},
		"x": {false: 'x', true: 'X'},
		"y": {false: 'y', true: 'Y'},
		"z": {false: 'z', true: 'Z'},
		
		// Numbers and symbols
		"0": {false: '0', true: ')'},
		"1": {false: '1', true: '!'},
		"2": {false: '2', true: '@'},
		"3": {false: '3', true: '#'},
		"4": {false: '4', true: '$'},
		"5": {false: '5', true: '%'},
		"6": {false: '6', true: '^'},
		"7": {false: '7', true: '&'},
		"8": {false: '8', true: '*'},
		"9": {false: '9', true: '('},
		
		// Punctuation
		"`":  {false: '`', true: '~'},
		"-":  {false: '-', true: '_'},
		"=":  {false: '=', true: '+'},
		"[":  {false: '[', true: '{'},
		"]":  {false: ']', true: '}'},
		"\\": {false: '\\', true: '|'},
		";":  {false: ';', true: ':'},
		"'":  {false: '\'', true: '"'},
		",":  {false: ',', true: '<'},
		".":  {false: '.', true: '>'},
		"/":  {false: '/', true: '?'},
	}
	
	// Russian layout (ЙЦУКЕН)
	klm.layouts[LayoutRussian] = map[string]map[bool]rune{
		// Letters
		"a": {false: 'ф', true: 'Ф'},
		"b": {false: 'и', true: 'И'},
		"c": {false: 'с', true: 'С'},
		"d": {false: 'в', true: 'В'},
		"e": {false: 'у', true: 'У'},
		"f": {false: 'а', true: 'А'},
		"g": {false: 'п', true: 'П'},
		"h": {false: 'р', true: 'Р'},
		"i": {false: 'ш', true: 'Ш'},
		"j": {false: 'о', true: 'О'},
		"k": {false: 'л', true: 'Л'},
		"l": {false: 'д', true: 'Д'},
		"m": {false: 'ь', true: 'Ь'},
		"n": {false: 'т', true: 'Т'},
		"o": {false: 'щ', true: 'Щ'},
		"p": {false: 'з', true: 'З'},
		"q": {false: 'й', true: 'Й'},
		"r": {false: 'к', true: 'К'},
		"s": {false: 'ы', true: 'Ы'},
		"t": {false: 'е', true: 'Е'},
		"u": {false: 'г', true: 'Г'},
		"v": {false: 'м', true: 'М'},
		"w": {false: 'ц', true: 'Ц'},
		"x": {false: 'ч', true: 'Ч'},
		"y": {false: 'н', true: 'Н'},
		"z": {false: 'я', true: 'Я'},
		
		// Numbers and symbols (same as US for now)
		"0": {false: '0', true: ')'},
		"1": {false: '1', true: '!'},
		"2": {false: '2', true: '"'},
		"3": {false: '3', true: '№'},
		"4": {false: '4', true: ';'},
		"5": {false: '5', true: '%'},
		"6": {false: '6', true: ':'},
		"7": {false: '7', true: '?'},
		"8": {false: '8', true: '*'},
		"9": {false: '9', true: '('},
		
		// Punctuation
		"`":  {false: 'ё', true: 'Ё'},
		"-":  {false: '-', true: '_'},
		"=":  {false: '=', true: '+'},
		"[":  {false: 'х', true: 'Х'},
		"]":  {false: 'ъ', true: 'Ъ'},
		"\\": {false: '\\', true: '/'},
		";":  {false: 'ж', true: 'Ж'},
		"'":  {false: 'э', true: 'Э'},
		",":  {false: 'б', true: 'Б'},
		".":  {false: 'ю', true: 'Ю'},
		"/":  {false: '.', true: ','},
	}
	
	// German layout (QWERTZ)
	klm.layouts[LayoutGerman] = map[string]map[bool]rune{
		// Letters (mostly same as US, but y and z are swapped)
		"a": {false: 'a', true: 'A'},
		"b": {false: 'b', true: 'B'},
		"c": {false: 'c', true: 'C'},
		"d": {false: 'd', true: 'D'},
		"e": {false: 'e', true: 'E'},
		"f": {false: 'f', true: 'F'},
		"g": {false: 'g', true: 'G'},
		"h": {false: 'h', true: 'H'},
		"i": {false: 'i', true: 'I'},
		"j": {false: 'j', true: 'J'},
		"k": {false: 'k', true: 'K'},
		"l": {false: 'l', true: 'L'},
		"m": {false: 'm', true: 'M'},
		"n": {false: 'n', true: 'N'},
		"o": {false: 'o', true: 'O'},
		"p": {false: 'p', true: 'P'},
		"q": {false: 'q', true: 'Q'},
		"r": {false: 'r', true: 'R'},
		"s": {false: 's', true: 'S'},
		"t": {false: 't', true: 'T'},
		"u": {false: 'u', true: 'U'},
		"v": {false: 'v', true: 'V'},
		"w": {false: 'w', true: 'W'},
		"x": {false: 'x', true: 'X'},
		"y": {false: 'z', true: 'Z'}, // Swapped with z
		"z": {false: 'y', true: 'Y'}, // Swapped with y
		
		// Numbers and symbols
		"0": {false: '0', true: '='},
		"1": {false: '1', true: '!'},
		"2": {false: '2', true: '"'},
		"3": {false: '3', true: '§'},
		"4": {false: '4', true: '$'},
		"5": {false: '5', true: '%'},
		"6": {false: '6', true: '&'},
		"7": {false: '7', true: '/'},
		"8": {false: '8', true: '('},
		"9": {false: '9', true: ')'},
		
		// Punctuation
		"`":  {false: '^', true: '°'},
		"-":  {false: 'ß', true: '?'},
		"=":  {false: '´', true: '`'},
		"[":  {false: 'ü', true: 'Ü'},
		"]":  {false: '+', true: '*'},
		"\\": {false: '#', true: '\''},
		";":  {false: 'ö', true: 'Ö'},
		"'":  {false: 'ä', true: 'Ä'},
		",":  {false: ',', true: ';'},
		".":  {false: '.', true: ':'},
		"/":  {false: '-', true: '_'},
	}
}

// GetCharForKey returns the character for a given key and shift state
func (klm *KeyboardLayoutManager) GetCharForKey(key string, shiftPressed bool) (rune, bool) {
	klm.mu.RLock()
	defer klm.mu.RUnlock()
	
	layout, ok := klm.layouts[klm.currentLayout]
	if !ok {
		return 0, false
	}
	
	keyMap, ok := layout[key]
	if !ok {
		return 0, false
	}
	
	char, ok := keyMap[shiftPressed]
	return char, ok
}

// SwitchLayout switches to the next available layout
func (klm *KeyboardLayoutManager) SwitchLayout() KeyboardLayout {
	klm.mu.Lock()
	defer klm.mu.Unlock()
	
	// Define the order of layouts
	layouts := []KeyboardLayout{LayoutUS, LayoutRussian, LayoutGerman}
	
	// Find current layout index
	currentIndex := 0
	for i, layout := range layouts {
		if layout == klm.currentLayout {
			currentIndex = i
			break
		}
	}
	
	// Switch to next layout (wrap around)
	nextIndex := (currentIndex + 1) % len(layouts)
	klm.currentLayout = layouts[nextIndex]
	
	return klm.currentLayout
}

// SetLayout sets a specific keyboard layout
func (klm *KeyboardLayoutManager) SetLayout(layout KeyboardLayout) {
	klm.mu.Lock()
	defer klm.mu.Unlock()
	klm.currentLayout = layout
}

// GetCurrentLayout returns the current keyboard layout
func (klm *KeyboardLayoutManager) GetCurrentLayout() KeyboardLayout {
	klm.mu.RLock()
	defer klm.mu.RUnlock()
	return klm.currentLayout
}

// GetLayoutName returns a human-readable name for the layout
func (klm *KeyboardLayoutManager) GetLayoutName(layout KeyboardLayout) string {
	switch layout {
	case LayoutUS:
		return "English (US)"
	case LayoutRussian:
		return "Russian (ЙЦУКЕН)"
	case LayoutGerman:
		return "German (QWERTZ)"
	default:
		return string(layout)
	}
}
