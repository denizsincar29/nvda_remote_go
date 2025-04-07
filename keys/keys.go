package keys

import (
	"fmt"
	"strings"
)

// vkKey is used as a composite key for the byCode map.
// The extended field uses a pointer to differentiate between
// false, true, and irrelevant (nil).
type vkKey struct {
	vkCode   int
	extended *bool // nil means irrelevant, &true means true, &false means false
}

// KeyInfo holds the virtual key code, extended flag, and scan code for a key.
// This struct is designed to be easily marshalable/unmarshalable to/from JSON.
type KeyInfo struct {
	VKCode   int   `json:"vk_code"`
	Extended *bool `json:"extended"`  // Use pointer to handle null from JSON (which defaults to false if needed)
	ScanCode *int  `json:"scan_code"` // Allows nil scan codes
}

var (
	// byCode maps (vkCode, extended) to key name.
	// extended = nil means the extended state is irrelevant.
	byCode map[vkKey]string

	// byName maps lower-case key names to their (vkCode, extended) representation.
	byName map[string]vkKey

	// scanCodesByName maps lower-case key names to their scan code (as a pointer).
	// WARNING: This map is based on the limited provided reference and common
	//          PC/AT Set 1 scan codes. Scan codes can be complex (make/break,
	//          prefix bytes like E0/E1, different sets). This map might be
	//          incomplete or inaccurate for some systems or specific keys.
	//          A nil value means the scan code is unknown or not applicable here.
	scanCodesByName map[string]*int

	// Helper pointers for boolean values used in map keys
	trueVal  = true
	falseVal = false
)

// Helper function to create a pointer to an int literal.
func intPtr(i int) *int {
	return &i
}

// init initializes the key mapping dictionaries.
func init() {
	byCode = make(map[vkKey]string)
	byName = make(map[string]vkKey)
	scanCodesByName = make(map[string]*int)

	// --- Populate byCode map based on the Python reference ---
	// Helper function to add entries
	addKey := func(vk int, ext *bool, name string) {
		key := vkKey{vkCode: vk, extended: ext}
		byCode[key] = name

		// Populate the reverse map (byName)
		lowerName := strings.ToLower(name)
		// Only add to byName if not already present, preferring non-nil extended keys
		// or the first one encountered if both are nil/non-nil.
		if _, exists := byName[lowerName]; !exists || ext != nil {
			byName[lowerName] = key
		}
	}

	addKey(0x01, nil, "leftMouse")
	addKey(0x02, nil, "rightMouse")
	addKey(0x03, nil, "break")
	addKey(0x04, nil, "middleMouse")
	addKey(0x08, nil, "backspace")
	addKey(0x09, nil, "tab")
	addKey(0x0C, nil, "numpad5") // Note: Python VK for this is 0x0C, typically numlock off. Scan code 76.
	addKey(0x0D, &falseVal, "enter")
	addKey(0x0D, &trueVal, "numpadEnter") // Usually requires E0 prefix
	addKey(0x10, nil, "shift")            // Generic shift
	addKey(0x11, nil, "control")          // Generic control
	addKey(0x12, nil, "alt")              // Generic alt
	addKey(0x13, nil, "pause")
	addKey(0x14, nil, "capsLock")
	addKey(0x18, nil, "IMEFinalMode")
	addKey(0x1B, nil, "escape")
	addKey(0x1C, nil, "IMEConvert")
	addKey(0x1D, nil, "IMENonconvert")
	addKey(0x1E, nil, "IMEAccept")
	addKey(0x1F, nil, "IMEModeChange")
	addKey(0x20, nil, "space")
	addKey(0x21, &trueVal, "pageUp")
	addKey(0x21, &falseVal, "numpad9")
	addKey(0x22, &trueVal, "pageDown")
	addKey(0x22, &falseVal, "numpad3")
	addKey(0x23, &trueVal, "end")
	addKey(0x23, &falseVal, "numpad1")
	addKey(0x24, &trueVal, "home")
	addKey(0x24, &falseVal, "numpad7")
	addKey(0x25, &trueVal, "leftArrow")
	addKey(0x25, &falseVal, "numpad4")
	addKey(0x26, &trueVal, "upArrow")
	addKey(0x26, &falseVal, "numpad8")
	addKey(0x27, &trueVal, "rightArrow")
	addKey(0x27, &falseVal, "numpad6")
	addKey(0x28, &trueVal, "downArrow")
	addKey(0x28, &falseVal, "numpad2")
	addKey(0x29, nil, "select")
	addKey(0x2A, nil, "print")
	addKey(0x2B, nil, "execute")
	addKey(0x2C, nil, "printScreen")
	addKey(0x2D, &trueVal, "insert")
	addKey(0x2D, &falseVal, "numpadInsert") // VK_NUMPAD0 with NumLock off
	addKey(0x2E, &trueVal, "delete")
	addKey(0x2E, &falseVal, "numpadDelete") // VK_DECIMAL with NumLock off
	addKey(0x2F, nil, "help")
	// Add 0-9 keys (VK 0x30 - 0x39)
	for i := 0; i <= 9; i++ {
		addKey(0x30+i, nil, fmt.Sprintf("%d", i))
	}
	// Add A-Z keys (VK 0x41 - 0x5A)
	for i := 0; i < 26; i++ {
		addKey(0x41+i, nil, string('a'+byte(i)))
	}
	addKey(0x5B, nil, "leftWindows")
	addKey(0x5C, nil, "rightWindows")
	addKey(0x5D, nil, "applications")
	addKey(0x5F, nil, "sleep")
	addKey(0x60, nil, "numLockNumpad0") // VK_NUMPAD0 with NumLock on
	addKey(0x61, nil, "numLockNumpad1") // VK_NUMPAD1 with NumLock on
	addKey(0x62, nil, "numLockNumpad2")
	addKey(0x63, nil, "numLockNumpad3")
	addKey(0x64, nil, "numLockNumpad4")
	addKey(0x65, nil, "numLockNumpad5")
	addKey(0x66, nil, "numLockNumpad6")
	addKey(0x67, nil, "numLockNumpad7")
	addKey(0x68, nil, "numLockNumpad8")
	addKey(0x69, nil, "numLockNumpad9")
	addKey(0x6A, nil, "numpadMultiply")
	addKey(0x6B, nil, "numpadPlus")
	addKey(0x6C, nil, "numpadSeparator") // Usually Enter on numpad? Python doesn't specify. Map has numpadEnter separately.
	addKey(0x6D, nil, "numpadMinus")
	addKey(0x6E, nil, "numpadDecimal") // VK_DECIMAL with NumLock on
	addKey(0x6F, nil, "numpadDivide")
	// F1-F24 (VK 0x70 - 0x87)
	for i := 1; i <= 24; i++ {
		addKey(0x70+i-1, nil, fmt.Sprintf("f%d", i))
	}
	addKey(0x90, nil, "numLock")
	addKey(0x91, nil, "scrollLock")
	addKey(0xA0, nil, "leftShift")
	addKey(0xA1, nil, "rightShift")
	addKey(0xA2, nil, "leftControl")
	addKey(0xA3, nil, "rightControl") // Usually requires E0 prefix
	addKey(0xA4, nil, "leftAlt")
	addKey(0xA5, nil, "rightAlt") // Usually requires E0 prefix
	addKey(0xA6, nil, "browserBack")
	addKey(0xA7, nil, "browserForward")
	addKey(0xA8, nil, "browserRefresh")
	addKey(0xA9, nil, "browserStop")
	addKey(0xAA, nil, "browserSearch")
	addKey(0xAB, nil, "browserFavorites")
	addKey(0xAC, nil, "browserHome")
	addKey(0xAD, nil, "volumeMute")
	addKey(0xAE, nil, "volumeDown")
	addKey(0xAF, nil, "volumeUp")
	addKey(0xB0, nil, "mediaNextTrack")
	addKey(0xB1, nil, "mediaPrevTrack")
	addKey(0xB2, nil, "mediaStop")
	addKey(0xB3, nil, "mediaPlayPause")
	addKey(0xB4, nil, "launchMail")
	addKey(0xB5, nil, "launchMediaPlayer")
	addKey(0xB6, nil, "launchApp1")
	addKey(0xB7, nil, "launchApp2")
	// Add OEM keys from Python reference (typically punctuation)
	addKey(0xBA, nil, ";")  // VK_OEM_1 (`;:`)
	addKey(0xBB, nil, "=")  // VK_OEM_PLUS (`=+`)
	addKey(0xBC, nil, ",")  // VK_OEM_COMMA (`,<`)
	addKey(0xBD, nil, "-")  // VK_OEM_MINUS (`-_`)
	addKey(0xBE, nil, ".")  // VK_OEM_PERIOD (`.>`)
	addKey(0xBF, nil, "/")  // VK_OEM_2 (`/?`)
	addKey(0xC0, nil, "`")  // VK_OEM_3 (``~`)
	addKey(0xDB, nil, "[")  // VK_OEM_4 (`[{`)
	addKey(0xDC, nil, "\\") // VK_OEM_5 (`\|`)
	addKey(0xDD, nil, "]")  // VK_OEM_6 (`]}`)
	addKey(0xDE, nil, "'")  // VK_OEM_7 (`'"`)
	// addKey(0xE7, nil, "vkPacket") // Not a real key press, used for unicode input

	// --- Populate scanCodesByName map ---
	// Based on user list and standard US Keyboard Layout Scan Codes (Set 1)
	// WARNING: This is a simplified mapping and may not cover all keyboard layouts
	// or handle extended codes (E0 prefix) correctly. Use pointers now.
	scanCodesByName["escape"] = intPtr(1)
	scanCodesByName["1"] = intPtr(2)
	scanCodesByName["2"] = intPtr(3)
	scanCodesByName["3"] = intPtr(4)
	scanCodesByName["4"] = intPtr(5)
	scanCodesByName["5"] = intPtr(6)
	scanCodesByName["6"] = intPtr(7)
	scanCodesByName["7"] = intPtr(8)
	scanCodesByName["8"] = intPtr(9)
	scanCodesByName["9"] = intPtr(10)
	scanCodesByName["0"] = intPtr(11)
	scanCodesByName["-"] = intPtr(12) // Corresponds to VK_OEM_MINUS
	scanCodesByName["="] = intPtr(13) // Corresponds to VK_OEM_PLUS
	scanCodesByName["backspace"] = intPtr(14)
	scanCodesByName["tab"] = intPtr(15)
	scanCodesByName["q"] = intPtr(16)
	scanCodesByName["w"] = intPtr(17)
	scanCodesByName["e"] = intPtr(18)
	scanCodesByName["r"] = intPtr(19)
	scanCodesByName["t"] = intPtr(20)
	scanCodesByName["y"] = intPtr(21)
	scanCodesByName["u"] = intPtr(22)
	scanCodesByName["i"] = intPtr(23)
	scanCodesByName["o"] = intPtr(24)
	scanCodesByName["p"] = intPtr(25)
	scanCodesByName["["] = intPtr(26) // Corresponds to VK_OEM_4
	scanCodesByName["]"] = intPtr(27) // Corresponds to VK_OEM_6
	scanCodesByName["enter"] = intPtr(28)
	scanCodesByName["leftcontrol"] = intPtr(29) // Map specific modifier
	scanCodesByName["control"] = intPtr(29)     // Map generic modifier (use left)
	scanCodesByName["a"] = intPtr(30)
	scanCodesByName["s"] = intPtr(31)
	scanCodesByName["d"] = intPtr(32)
	scanCodesByName["f"] = intPtr(33)
	scanCodesByName["g"] = intPtr(34)
	scanCodesByName["h"] = intPtr(35)
	scanCodesByName["j"] = intPtr(36)
	scanCodesByName["k"] = intPtr(37)
	scanCodesByName["l"] = intPtr(38)
	scanCodesByName[";"] = intPtr(39)         // Corresponds to VK_OEM_1
	scanCodesByName["'"] = intPtr(40)         // Corresponds to VK_OEM_7
	scanCodesByName["`"] = intPtr(41)         // Corresponds to VK_OEM_3
	scanCodesByName["leftshift"] = intPtr(42) // Map specific modifier
	scanCodesByName["shift"] = intPtr(42)     // Map generic modifier (use left)
	scanCodesByName["\\"] = intPtr(43)        // Corresponds to VK_OEM_5
	scanCodesByName["z"] = intPtr(44)
	scanCodesByName["x"] = intPtr(45)
	scanCodesByName["c"] = intPtr(46)
	scanCodesByName["v"] = intPtr(47)
	scanCodesByName["b"] = intPtr(48)
	scanCodesByName["n"] = intPtr(49)
	scanCodesByName["m"] = intPtr(50)
	scanCodesByName[","] = intPtr(51) // Corresponds to VK_OEM_COMMA
	scanCodesByName["."] = intPtr(52) // Corresponds to VK_OEM_PERIOD
	scanCodesByName["/"] = intPtr(53) // Corresponds to VK_OEM_2
	scanCodesByName["rightshift"] = intPtr(54)
	scanCodesByName["numpadmultiply"] = intPtr(55) // Usually shares with PrtSc on older keyboards
	scanCodesByName["printscreen"] = intPtr(55)    // User list value
	scanCodesByName["leftalt"] = intPtr(56)        // Map specific modifier
	scanCodesByName["alt"] = intPtr(56)            // Map generic modifier (use left)
	scanCodesByName["space"] = intPtr(57)
	scanCodesByName["capslock"] = intPtr(58)
	scanCodesByName["f1"] = intPtr(59)
	scanCodesByName["f2"] = intPtr(60)
	scanCodesByName["f3"] = intPtr(61)
	scanCodesByName["f4"] = intPtr(62)
	scanCodesByName["f5"] = intPtr(63)
	scanCodesByName["f6"] = intPtr(64)
	scanCodesByName["f7"] = intPtr(65)
	scanCodesByName["f8"] = intPtr(66)
	scanCodesByName["f9"] = intPtr(67)
	scanCodesByName["f10"] = intPtr(68)
	scanCodesByName["numlock"] = intPtr(69)
	scanCodesByName["scrolllock"] = intPtr(70)
	scanCodesByName["numpad7"] = intPtr(71)        // NumLock off: Home
	scanCodesByName["numlocknumpad7"] = intPtr(71) // NumLock on: 7
	scanCodesByName["home"] = intPtr(71)           // Often shares scancode 71 on numpad block
	scanCodesByName["numpad8"] = intPtr(72)        // NumLock off: Up
	scanCodesByName["numlocknumpad8"] = intPtr(72) // NumLock on: 8
	scanCodesByName["uparrow"] = intPtr(72)        // Often shares scancode 72 on numpad block
	scanCodesByName["numpad9"] = intPtr(73)        // NumLock off: PgUp
	scanCodesByName["numlocknumpad9"] = intPtr(73) // NumLock on: 9
	scanCodesByName["pageup"] = intPtr(73)         // Often shares scancode 73 on numpad block
	scanCodesByName["numpadminus"] = intPtr(74)
	scanCodesByName["numpad4"] = intPtr(75)        // NumLock off: Left
	scanCodesByName["numlocknumpad4"] = intPtr(75) // NumLock on: 4
	scanCodesByName["leftarrow"] = intPtr(75)      // Often shares scancode 75 on numpad block
	scanCodesByName["numpad5"] = intPtr(76)        // NumLock off: Clear (sometimes 5)
	scanCodesByName["numlocknumpad5"] = intPtr(76) // NumLock on: 5
	scanCodesByName["numpad6"] = intPtr(77)        // NumLock off: Right
	scanCodesByName["numlocknumpad6"] = intPtr(77) // NumLock on: 6
	scanCodesByName["rightarrow"] = intPtr(77)     // Often shares scancode 77 on numpad block
	scanCodesByName["numpadplus"] = intPtr(78)
	scanCodesByName["numpad1"] = intPtr(79)        // NumLock off: End
	scanCodesByName["numlocknumpad1"] = intPtr(79) // NumLock on: 1
	scanCodesByName["end"] = intPtr(79)            // Often shares scancode 79 on numpad block
	scanCodesByName["numpad2"] = intPtr(80)        // NumLock off: Down
	scanCodesByName["numlocknumpad2"] = intPtr(80) // NumLock on: 2
	scanCodesByName["downarrow"] = intPtr(80)      // Often shares scancode 80 on numpad block
	scanCodesByName["numpad3"] = intPtr(81)        // NumLock off: PgDn
	scanCodesByName["numlocknumpad3"] = intPtr(81) // NumLock on: 3
	scanCodesByName["pagedown"] = intPtr(81)       // Often shares scancode 81 on numpad block
	scanCodesByName["numpadinsert"] = intPtr(82)   // NumLock off: Ins
	scanCodesByName["numlocknumpad0"] = intPtr(82) // NumLock on: 0
	scanCodesByName["insert"] = intPtr(82)         // Often shares scancode 82 on numpad block
	scanCodesByName["numpaddelete"] = intPtr(83)   // NumLock off: Del
	scanCodesByName["numpaddecimal"] = intPtr(83)  // NumLock on: .
	scanCodesByName["delete"] = intPtr(83)         // Often shares scancode 83 on numpad block

	// Scan codes for F11, F12 etc. are often different across keyboards or require E0/E1 prefixes.
	scanCodesByName["f11"] = intPtr(87) // Common PC/AT
	scanCodesByName["f12"] = intPtr(88) // Common PC/AT

	// Scan codes for extended keys (like right ctrl, right alt, numpad enter, arrow cluster, etc.)
	// often involve an E0 prefix and are not included in this basic map.
	// E.g., Right Ctrl is E0 1D, Numpad Enter is E0 1C, Right Alt is E0 38
	// The current map might incorrectly map some keys if only the base scancode is used.
	// We assign the base scan code here, but acknowledge the need for prefix handling elsewhere.
	scanCodesByName["rightcontrol"] = intPtr(29) // Same base scancode as left, needs E0 prefix usually
	scanCodesByName["rightalt"] = intPtr(56)     // Same base scancode as left, needs E0 prefix usually
	scanCodesByName["numpadenter"] = intPtr(28)  // Same base scancode as main enter, needs E0 prefix usually
	// Note: VK 0x6C (NumpadSeparator) might also map here on some kbs.

	// Add missing punctuation etc. if needed, ensuring they map to correct VK codes too.
	// Keys like Mouse buttons, Pause, Sleep, Media keys often don't have standard Set 1 scan codes
	// or use complex sequences, so they are left as nil here.
	scanCodesByName["leftmouse"] = nil
	scanCodesByName["rightmouse"] = nil
	scanCodesByName["middlemouse"] = nil
	scanCodesByName["break"] = nil        // Often E1 1D 45 E1 9D C5 or just E0 46
	scanCodesByName["pause"] = nil        // See break
	scanCodesByName["leftwindows"] = nil  // Typically E0 5B
	scanCodesByName["rightwindows"] = nil // Typically E0 5C
	scanCodesByName["applications"] = nil // Typically E0 5D
	scanCodesByName["sleep"] = nil        // Typically E0 5F
	// Numpad Separator (VK 0x6C) is ambiguous, often Enter or sometimes unique
	scanCodesByName["numpadseparator"] = nil // Could be E0 1C (like Numpad Enter)
	scanCodesByName["numpaddivide"] = nil    // Typically E0 35
	// Media keys often use E0 prefix + specific code
	scanCodesByName["browserback"] = nil       // E0 6A
	scanCodesByName["browserforward"] = nil    // E0 69
	scanCodesByName["browserrefresh"] = nil    // E0 67
	scanCodesByName["browserstop"] = nil       // E0 68
	scanCodesByName["browsersearch"] = nil     // E0 65
	scanCodesByName["browserfavorites"] = nil  // E0 66
	scanCodesByName["browserhome"] = nil       // E0 32
	scanCodesByName["volumemute"] = nil        // E0 20
	scanCodesByName["volumedown"] = nil        // E0 2E
	scanCodesByName["volumeup"] = nil          // E0 30
	scanCodesByName["medianexttrack"] = nil    // E0 19
	scanCodesByName["mediaprevtrack"] = nil    // E0 10
	scanCodesByName["mediastop"] = nil         // E0 24
	scanCodesByName["mediaplaypause"] = nil    // E0 22
	scanCodesByName["launchmail"] = nil        // E0 6C
	scanCodesByName["launchmediaplayer"] = nil // E0 6D
	scanCodesByName["launchapp1"] = nil        // E0 6B
	scanCodesByName["launchapp2"] = nil        // E0 21
	// Other misc keys
	scanCodesByName["select"] = nil
	scanCodesByName["print"] = nil // Usually involved with Shift+PrtScn sequences
	scanCodesByName["execute"] = nil
	scanCodesByName["help"] = nil // Often E0 63

}

// GetKeyInfo translates a key name (e.g., "enter", "a", "leftShift", "numpad5")
// into its corresponding VK code, extended flag, and scan code.
// The key name matching is case-insensitive.
// It returns a KeyInfo struct and an error only if the key name itself is not found.
// If the scan code for the key name is not defined in the map, KeyInfo.ScanCode will be nil.
func GetKeyInfo(keyName string) (KeyInfo, error) {
	lowerName := strings.ToLower(keyName)

	vkKeyData, nameFound := byName[lowerName]
	if !nameFound {
		return KeyInfo{}, fmt.Errorf("key name not found: %s", keyName)
	}

	// Look up the scan code pointer from the map.
	// If the key name exists in scanCodesByName, scanCode will be the *int.
	// If the key name does NOT exist in scanCodesByName, scanCode will be nil.
	scanCode := scanCodesByName[lowerName] // No need for the second return value `scanCodeFound` here

	// Determine the boolean value for Extended. If vkKeyData.extended is nil (irrelevant),
	// default to false when sending, as non-extended is the common case.
	extendedVal := false // Default
	if vkKeyData.extended != nil {
		extendedVal = *vkKeyData.extended
	}

	info := KeyInfo{
		VKCode:   vkKeyData.vkCode,
		Extended: &extendedVal, // Return a pointer to the determined boolean value
		ScanCode: scanCode,     // Assign the *int pointer directly (it might be nil)
	}

	return info, nil
}

// GetKeyName translates a VK code and an extended flag into the corresponding key name.
// The extended flag is a pointer; if nil is received (e.g., from JSON where it was null or omitted),
// it will be treated as false.
// It first checks for a specific match (vkCode + extended flag value).
// If no specific match is found, it checks if there's a mapping where the extended flag is irrelevant (nil).
// Returns the key name string and an error if no corresponding key name is found.
func GetKeyName(vkCode int, extended *bool) (string, error) {
	// Determine the effective boolean value for the extended flag.
	// Treat nil input as false, as per the requirement.
	effectiveExtended := false
	if extended != nil {
		effectiveExtended = *extended
	}

	// 1. Try matching with the specific (or effective) extended value
	var keyName string
	var found bool

	if effectiveExtended {
		keyName, found = byCode[vkKey{vkCode: vkCode, extended: &trueVal}]
	} else {
		keyName, found = byCode[vkKey{vkCode: vkCode, extended: &falseVal}]
	}

	if found {
		return keyName, nil
	}

	// 2. If not found, try matching with irrelevant extended flag (nil)
	keyName, found = byCode[vkKey{vkCode: vkCode, extended: nil}]
	if found {
		return keyName, nil
	}

	// 3. If still not found, return an error
	extStr := "false"
	if extended != nil {
		extStr = fmt.Sprintf("%v", *extended)
	} else {
		extStr = "nil (treated as false)"
	}
	return "", fmt.Errorf("key name not found for VKCode: 0x%X, Extended: %s", vkCode, extStr)
}
