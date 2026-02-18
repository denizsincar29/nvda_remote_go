package vgui

import (
	"strings"
	"testing"
)

// TestLocalization tests the localization system
func TestLocalization(t *testing.T) {
	// Test English
	locEn := NewLocalizer(LocaleEnglish)
	if locEn.T("button") != "button" {
		t.Errorf("Expected 'button', got '%s'", locEn.T("button"))
	}
	if locEn.T("checked") != "checked" {
		t.Errorf("Expected 'checked', got '%s'", locEn.T("checked"))
	}
	
	// Test Russian
	locRu := NewLocalizer(LocaleRussian)
	if locRu.T("button") != "кнопка" {
		t.Errorf("Expected 'кнопка', got '%s'", locRu.T("button"))
	}
	if locRu.T("checked") != "установлен" {
		t.Errorf("Expected 'установлен', got '%s'", locRu.T("checked"))
	}
	
	// Test German
	locDe := NewLocalizer(LocaleGerman)
	if locDe.T("button") != "Schaltfläche" {
		t.Errorf("Expected 'Schaltfläche', got '%s'", locDe.T("button"))
	}
	if locDe.T("checked") != "aktiviert" {
		t.Errorf("Expected 'aktiviert', got '%s'", locDe.T("checked"))
	}
	
	// Test fallback for unknown key
	unknown := locEn.T("unknown_key")
	if unknown != "unknown_key" {
		t.Errorf("Expected 'unknown_key', got '%s'", unknown)
	}
}

// TestGUIWithLocale tests GUI with different locales
func TestGUIWithLocale(t *testing.T) {
	gui := NewGUI(WithLocale(LocaleRussian))
	
	button := NewButton("Test")
	gui.AddElement(button)
	
	desc := button.GetDescription()
	if !strings.Contains(desc, "кнопка") {
		t.Errorf("Expected Russian role 'кнопка' in description, got '%s'", desc)
	}
}

// TestDefaultButton tests default button behavior
func TestDefaultButton(t *testing.T) {
	gui := NewGUI()
	
	button1 := NewButton("Button 1")
	button2 := NewButton("OK")
	button2.IsDefault = true
	
	gui.AddElement(button1)
	gui.AddElement(button2)
	
	// Check that button2 is tracked as default
	if gui.GetDefaultButton() != button2 {
		t.Error("Expected button2 to be the default button")
	}
	
	// Enter key should activate default button, not focused element
	activated := false
	button2.OnClick = func() string {
		activated = true
		return "OK pressed"
	}
	
	result := gui.HandleKey("enter", true)
	if !activated {
		t.Error("Default button should have been activated")
	}
	if result != "OK pressed" {
		t.Errorf("Expected 'OK pressed', got '%s'", result)
	}
}

// TestHotkeySystem tests hotkey registration and execution
func TestHotkeySystem(t *testing.T) {
	gui := NewGUI()
	
	saveCalled := false
	gui.RegisterHotkey("ctrl+s", func() string {
		saveCalled = true
		return "File saved"
	})
	
	// Test hotkey execution
	result := gui.HandleKeyWithModifiers("s", []string{"ctrl"}, true)
	if !saveCalled {
		t.Error("Hotkey callback should have been called")
	}
	if result != "File saved" {
		t.Errorf("Expected 'File saved', got '%s'", result)
	}
	
	// Test duplicate registration
	err := gui.RegisterHotkey("ctrl+s", func() string {
		return "Another callback"
	})
	if err == nil {
		t.Error("Should have returned error for duplicate hotkey")
	}
	
	// Test unregister
	gui.UnregisterHotkey("ctrl+s")
	hotkeys := gui.GetRegisteredHotkeys()
	if len(hotkeys) != 0 {
		t.Errorf("Expected 0 hotkeys, got %d", len(hotkeys))
	}
}

// TestDialog tests dialog creation and standard buttons
func TestDialog(t *testing.T) {
	config := DialogConfig{
		HasOK:     true,
		HasCancel: true,
	}
	
	dialog := NewDialog(config)
	dialog.AddElement(NewLabel("Test dialog"))
	dialog.AddStandardButtons()
	
	// Check that buttons were created
	if dialog.okButton == nil {
		t.Error("OK button should have been created")
	}
	if dialog.cancelButton == nil {
		t.Error("Cancel button should have been created")
	}
	
	// Check that OK button is default
	if !dialog.okButton.IsDefault {
		t.Error("OK button should be default")
	}
	
	// Test result callback
	resultReceived := ""
	dialog.OnResult = func(result string) string {
		resultReceived = result
		return "Result: " + result
	}
	
	// Activate OK button
	dialog.okButton.OnActivate()
	if resultReceived != "ok" {
		t.Errorf("Expected result 'ok', got '%s'", resultReceived)
	}
	
	// Test Escape key
	dialog.cancelButton.OnActivate()
	if resultReceived != "cancel" {
		t.Errorf("Expected result 'cancel', got '%s'", resultReceived)
	}
}

// TestConfirmDialog tests confirmation dialog
func TestConfirmDialog(t *testing.T) {
	dialog := NewConfirmDialog("Are you sure?")
	
	confirmed := false
	dialog.SetConfirmCallback(func(c bool) string {
		confirmed = c
		if c {
			return "Confirmed"
		}
		return "Cancelled"
	})
	
	// Activate Yes button
	if dialog.yesButton == nil {
		t.Fatal("Yes button should have been created")
	}
	result := dialog.yesButton.OnActivate()
	if !confirmed {
		t.Error("Should have been confirmed")
	}
	if result != "Confirmed" {
		t.Errorf("Expected 'Confirmed', got '%s'", result)
	}
	
	// Activate No button
	if dialog.noButton == nil {
		t.Fatal("No button should have been created")
	}
	result = dialog.noButton.OnActivate()
	if confirmed {
		t.Error("Should not have been confirmed")
	}
	if result != "Cancelled" {
		t.Errorf("Expected 'Cancelled', got '%s'", result)
	}
}

// TestTextBox tests textbox functionality
func TestTextBox(t *testing.T) {
	textbox := NewTextBox("Test", "Hello World")
	textbox.SetCursorPosition(0)
	
	// Test move right
	result := textbox.MoveRight()
	if result != "e" {
		t.Errorf("Expected 'e', got '%s'", result)
	}
	
	// Test move to space
	textbox.SetCursorPosition(4)  // Position before space
	result = textbox.MoveRight()
	if result != "blank" {
		t.Errorf("Expected 'blank' for space, got '%s'", result)
	}
	
	// Test move left
	textbox.SetCursorPosition(1)
	result = textbox.MoveLeft()
	if result != "H" {
		t.Errorf("Expected 'H', got '%s'", result)
	}
	
	// Test move to start
	textbox.SetCursorPosition(5)
	result = textbox.MoveToStart()
	if result != "H" {
		t.Errorf("Expected 'H', got '%s'", result)
	}
	
	// Test move to end
	result = textbox.MoveToEnd()
	if result != "end of text" {
		t.Errorf("Expected 'end of text', got '%s'", result)
	}
	
	// Test character insertion
	textbox.SetCursorPosition(5)
	result = textbox.InsertChar('!')
	if result != "!" {
		t.Errorf("Expected '!', got '%s'", result)
	}
	if textbox.Text != "Hello! World" {
		t.Errorf("Expected 'Hello! World', got '%s'", textbox.Text)
	}
	
	// Test delete character
	textbox.SetCursorPosition(6)
	result = textbox.DeleteCharBefore()
	if result != "!" {
		t.Errorf("Expected '!', got '%s'", result)
	}
	if textbox.Text != "Hello World" {
		t.Errorf("Expected 'Hello World', got '%s'", textbox.Text)
	}
}

// TestTextBoxWordNavigation tests word navigation in textbox
func TestTextBoxWordNavigation(t *testing.T) {
	textbox := NewTextBox("Test", "Hello World Test")
	textbox.SetCursorPosition(0)
	
	// Test move to next word
	result := textbox.MoveToNextWord()
	if result != "World" {
		t.Errorf("Expected 'World', got '%s'", result)
	}
	
	// Test move to next word again
	result = textbox.MoveToNextWord()
	if result != "Test" {
		t.Errorf("Expected 'Test', got '%s'", result)
	}
	
	// Test move to previous word
	result = textbox.MoveToPreviousWord()
	if result != "World" {
		t.Errorf("Expected 'World', got '%s'", result)
	}
}

// TestTextArea tests textarea functionality
func TestTextArea(t *testing.T) {
	textarea := NewTextArea("Test", "Line 1\nLine 2\nLine 3")
	
	// Test initial state
	if textarea.row != 0 {
		t.Errorf("Expected row 0, got %d", textarea.row)
	}
	
	// Test move down
	result := textarea.MoveDown()
	if result != "Line 2" {
		t.Errorf("Expected 'Line 2', got '%s'", result)
	}
	if textarea.row != 1 {
		t.Errorf("Expected row 1, got %d", textarea.row)
	}
	
	// Test move up
	result = textarea.MoveUp()
	if result != "Line 1" {
		t.Errorf("Expected 'Line 1', got '%s'", result)
	}
	if textarea.row != 0 {
		t.Errorf("Expected row 0, got %d", textarea.row)
	}
	
	// Test move to line start
	textarea.col = 3
	result = textarea.MoveToLineStart()
	if result != "L" {
		t.Errorf("Expected 'L', got '%s'", result)
	}
	if textarea.col != 0 {
		t.Errorf("Expected col 0, got %d", textarea.col)
	}
	
	// Test move to line end
	result = textarea.MoveToLineEnd()
	// Accept either "end of line" or "end of text" as valid
	if !strings.Contains(result, "end") {
		t.Errorf("Expected end of line message, got '%s'", result)
	}
	if textarea.col != len("Line 1") {
		t.Errorf("Expected col %d, got %d", len("Line 1"), textarea.col)
	}
}

// TestWindowManager tests window manager functionality
func TestWindowManager(t *testing.T) {
	wm := NewWindowManager(nil)
	
	gui1 := NewGUI()
	gui2 := NewGUI()
	
	wm.AddWindow("main", gui1)
	
	// Check active window
	active := wm.GetActiveWindow()
	if active != gui1 {
		t.Error("Expected gui1 to be active")
	}
	
	// Show modal
	gui3 := NewGUI()
	wm.ShowModal("modal", gui3)
	
	active = wm.GetActiveWindow()
	if active != gui3 {
		t.Error("Expected gui3 to be active after ShowModal")
	}
	
	// Close modal
	wm.CloseWindow("modal")
	
	active = wm.GetActiveWindow()
	// After closing modal, should return to "main" (gui1)
	if active != gui1 {
		t.Error("Expected gui1 to be active after closing modal")
	}
	
	// Add another window (not modal)
	wm.AddWindow("dialog", gui2)
	
	// Active should still be gui1 since AddWindow doesn't change active
	active = wm.GetActiveWindow()
	if active != gui1 {
		t.Error("Expected gui1 to still be active")
	}
	
	// Get window by name
	retrieved := wm.GetWindow("dialog")
	if retrieved != gui2 {
		t.Error("Expected to retrieve gui2 by name")
	}
}

// TestEscapeKey tests Escape key behavior in dialogs
func TestEscapeKey(t *testing.T) {
	config := DialogConfig{
		HasCancel: true,
	}
	
	dialog := NewDialog(config)
	dialog.AddStandardButtons()
	
	resultReceived := ""
	dialog.OnResult = func(result string) string {
		resultReceived = result
		return result
	}
	
	// Test Escape key
	dialog.HandleKey("escape", true)
	if resultReceived != "cancel" {
		t.Errorf("Expected 'cancel' from Escape key, got '%s'", resultReceived)
	}
}
