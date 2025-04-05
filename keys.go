package nvda_remote_go

import (
	"fmt"
	"strings"
)

type KeyCode struct {
	VK       int
	Extended bool
}

var (
	ByCode    = make(map[KeyCode]string)
	ByName    = make(map[string]KeyCode)
	ScanCodes = make(map[KeyCode]int)
)

func init() {
	entries := []struct {
		vk   int
		ext  *bool
		name string
		scan int
	}{
		// Mouse and basic keys
		{0x01, nil, "leftMouse", 0},
		{0x02, nil, "rightMouse", 0},
		{0x03, nil, "break", 0x46},
		{0x04, nil, "middleMouse", 0},
		{0x08, nil, "backspace", 0x0E},
		{0x09, nil, "tab", 0x0F},
		{0x0C, nil, "numpad5", 0x4C},
		{0x0D, boolPtr(false), "enter", 0x1C},
		{0x0D, boolPtr(true), "numpadEnter", 0xE01C},
		{0x10, nil, "shift", 0x2A},
		{0x11, nil, "control", 0x1D},
		{0x12, nil, "alt", 0x38},
		{0x13, nil, "pause", 0xC6},
		{0x14, nil, "capsLock", 0x3A},
		{0x18, nil, "IMEFinalMode", 0xE010},
		{0x1B, nil, "escape", 0x01},
		{0x1C, nil, "IMEConvert", 0x79},
		{0x1D, nil, "IMENonconvert", 0x7B},
		{0x1E, nil, "IMEAccept", 0},
		{0x1F, nil, "IMEModeChange", 0},

		// Navigation keys
		{0x20, nil, "space", 0x39},
		{0x21, boolPtr(true), "pageUp", 0x49},
		{0x21, boolPtr(false), "numpad9", 0x49},
		{0x22, boolPtr(true), "pageDown", 0x51},
		{0x22, boolPtr(false), "numpad3", 0x51},
		{0x23, boolPtr(true), "end", 0x4F},
		{0x23, boolPtr(false), "numpad1", 0x4F},
		{0x24, boolPtr(true), "home", 0x47},
		{0x24, boolPtr(false), "numpad7", 0x47},
		{0x25, boolPtr(true), "leftArrow", 0x4B},
		{0x25, boolPtr(false), "numpad4", 0x4B},
		{0x26, boolPtr(true), "upArrow", 0x48},
		{0x26, boolPtr(false), "numpad8", 0x48},
		{0x27, boolPtr(true), "rightArrow", 0x4D},
		{0x27, boolPtr(false), "numpad6", 0x4D},
		{0x28, boolPtr(true), "downArrow", 0x50},
		{0x28, boolPtr(false), "numpad2", 0x50},
		{0x29, nil, "select", 0},
		{0x2A, nil, "print", 0},
		{0x2B, nil, "execute", 0},
		{0x2C, nil, "printScreen", 0xE037},
		{0x2D, boolPtr(true), "insert", 0x52},
		{0x2D, boolPtr(false), "numpadInsert", 0x52},
		{0x2E, boolPtr(true), "delete", 0x53},
		{0x2E, boolPtr(false), "numpadDelete", 0x53},
		{0x2F, nil, "help", 0},

		// Function keys
		{0x70, nil, "f1", 0x3B},
		{0x71, nil, "f2", 0x3C},
		{0x72, nil, "f3", 0x3D},
		{0x73, nil, "f4", 0x3E},
		{0x74, nil, "f5", 0x3F},
		{0x75, nil, "f6", 0x40},
		{0x76, nil, "f7", 0x41},
		{0x77, nil, "f8", 0x42},
		{0x78, nil, "f9", 0x43},
		{0x79, nil, "f10", 0x44},
		{0x7A, nil, "f11", 0x57},
		{0x7B, nil, "f12", 0x58},
		{0x7C, nil, "f13", 0x64},
		{0x7D, nil, "f14", 0x65},
		{0x7E, nil, "f15", 0x66},
		{0x7F, nil, "f16", 0x67},
		{0x80, nil, "f17", 0x68},
		{0x81, nil, "f18", 0x69},
		{0x82, nil, "f19", 0x6A},
		{0x83, nil, "f20", 0x6B},
		{0x84, nil, "f21", 0x6C},
		{0x85, nil, "f22", 0x6D},
		{0x86, nil, "f23", 0x6E},
		{0x87, nil, "f24", 0x76},

		// Special keys
		{0x5B, nil, "leftWindows", 0xE05B},
		{0x5C, nil, "rightWindows", 0xE05C},
		{0x5D, nil, "applications", 0xE05D},
		{0x5F, nil, "sleep", 0xE05F},
		{0x90, nil, "numLock", 0x45},
		{0x91, nil, "scrollLock", 0x46},

		// Browser and media keys
		{0xA6, nil, "browserBack", 0xE06A},
		{0xA7, nil, "browserForward", 0xE069},
		{0xA8, nil, "browserRefresh", 0xE067},
		{0xA9, nil, "browserStop", 0xE068},
		{0xAA, nil, "browserSearch", 0xE065},
		{0xAB, nil, "browserFavorites", 0xE066},
		{0xAC, nil, "browserHome", 0xE032},
		{0xAD, nil, "volumeMute", 0xE020},
		{0xAE, nil, "volumeDown", 0xE02E},
		{0xAF, nil, "volumeUp", 0xE030},
		{0xB0, nil, "mediaNextTrack", 0xE019},
		{0xB1, nil, "mediaPrevTrack", 0xE010},
		{0xB2, nil, "mediaStop", 0xE024},
		{0xB3, nil, "mediaPlayPause", 0xE022},
		{0xB4, nil, "launchMail", 0xE06C},
		{0xB5, nil, "launchMediaPlayer", 0xE06D},
		{0xB6, nil, "launchApp1", 0xE021},
		{0xB7, nil, "launchApp2", 0xE06B},

		// Numpad keys
		{0x60, nil, "numLockNumpad0", 0x52},
		{0x61, nil, "numLockNumpad1", 0x4F},
		{0x62, nil, "numLockNumpad2", 0x50},
		{0x63, nil, "numLockNumpad3", 0x51},
		{0x64, nil, "numLockNumpad4", 0x4B},
		{0x65, nil, "numLockNumpad5", 0x4C},
		{0x66, nil, "numLockNumpad6", 0x4D},
		{0x67, nil, "numLockNumpad7", 0x47},
		{0x68, nil, "numLockNumpad8", 0x48},
		{0x69, nil, "numLockNumpad9", 0x49},
		{0x6A, nil, "numpadMultiply", 0x37},
		{0x6B, nil, "numpadPlus", 0x4E},
		{0x6C, nil, "numpadSeparator", 0x53},
		{0x6D, nil, "numpadMinus", 0x4A},
		{0x6E, nil, "numpadDecimal", 0x53},
		{0x6F, nil, "numpadDivide", 0xE035},

		// Modifier variants
		{0xA0, nil, "leftShift", 0x2A},
		{0xA1, nil, "rightShift", 0x36},
		{0xA2, nil, "leftControl", 0x1D},
		{0xA3, nil, "rightControl", 0xE01D},
		{0xA4, nil, "leftAlt", 0x38},
		{0xA5, nil, "rightAlt", 0xE038},
	}

	for _, entry := range entries {
		if entry.ext == nil {
			addEntry(entry.vk, false, entry.name, entry.scan)
			addEntry(entry.vk, true, entry.name, entry.scan)
		} else {
			addEntry(entry.vk, *entry.ext, entry.name, entry.scan)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

func addEntry(vk int, ext bool, name string, scan int) {
	code := KeyCode{vk, ext}
	ByCode[code] = name
	ByName[strings.ToLower(name)] = code
	ScanCodes[code] = scan
}

func GetKeyCode(name string) (int, int, bool) {
	code, exists := ByName[strings.ToLower(name)]
	if !exists {
		return 0, 0, false
	}
	return code.VK, ScanCodes[code], code.Extended
}

func GetKeyName(vk int, scan int, ext bool) string {
	// Try exact match first
	if name, exists := ByCode[KeyCode{vk, ext}]; exists {
		return name
	}

	// Try opposite extended state
	if name, exists := ByCode[KeyCode{vk, !ext}]; exists {
		return name
	}

	// Check for printable character
	if vk >= 0x20 && vk <= 0x7E {
		return string(rune(vk))
	}

	return fmt.Sprintf("Unknown (VK:0x%X, Scan:0x%X, Extended:%v)", vk, scan, ext)
}
