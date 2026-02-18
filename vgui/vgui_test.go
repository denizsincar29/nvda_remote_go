package vgui

import (
	"testing"
)

func TestButton(t *testing.T) {
	button := NewButton("Test Button")
	
	if button.GetName() != "Test Button" {
		t.Errorf("Expected name 'Test Button', got '%s'", button.GetName())
	}
	
	if button.GetRole() != RoleButton {
		t.Errorf("Expected role 'button', got '%s'", button.GetRole())
	}
	
	if !button.IsFocusable() {
		t.Error("Button should be focusable")
	}
	
	// Test callback
	callbackCalled := false
	button.OnClick = func() string {
		callbackCalled = true
		return "Button clicked"
	}
	
	result := button.OnActivate()
	if !callbackCalled {
		t.Error("OnClick callback should have been called")
	}
	
	if result != "Button clicked" {
		t.Errorf("Expected 'Button clicked', got '%s'", result)
	}
}

func TestListBox(t *testing.T) {
	items := []string{"Item 1", "Item 2", "Item 3"}
	listbox := NewListBox("Test List", items)
	
	if listbox.GetName() != "Test List" {
		t.Errorf("Expected name 'Test List', got '%s'", listbox.GetName())
	}
	
	if listbox.GetRole() != RoleListBox {
		t.Errorf("Expected role 'listbox', got '%s'", listbox.GetRole())
	}
	
	if !listbox.IsFocusable() {
		t.Error("ListBox should be focusable")
	}
	
	// Test initial selection
	if listbox.SelectedIndex != 0 {
		t.Errorf("Expected initial index 0, got %d", listbox.SelectedIndex)
	}
	
	if listbox.GetSelectedItem() != "Item 1" {
		t.Errorf("Expected 'Item 1', got '%s'", listbox.GetSelectedItem())
	}
	
	// Test move down
	result := listbox.MoveDown()
	if result != "Item 2" {
		t.Errorf("Expected 'Item 2', got '%s'", result)
	}
	
	if listbox.SelectedIndex != 1 {
		t.Errorf("Expected index 1, got %d", listbox.SelectedIndex)
	}
	
	// Test move up
	result = listbox.MoveUp()
	if result != "Item 1" {
		t.Errorf("Expected 'Item 1', got '%s'", result)
	}
	
	// Test boundary - move up at top
	result = listbox.MoveUp()
	if result != "Top of list" {
		t.Errorf("Expected 'Top of list', got '%s'", result)
	}
	
	// Test boundary - move down to bottom
	listbox.SelectedIndex = 2
	result = listbox.MoveDown()
	if result != "Bottom of list" {
		t.Errorf("Expected 'Bottom of list', got '%s'", result)
	}
}

func TestCheckBox(t *testing.T) {
	checkbox := NewCheckBox("Test CheckBox", false)
	
	if checkbox.GetName() != "Test CheckBox" {
		t.Errorf("Expected name 'Test CheckBox', got '%s'", checkbox.GetName())
	}
	
	if checkbox.GetRole() != RoleCheckBox {
		t.Errorf("Expected role 'checkbox', got '%s'", checkbox.GetRole())
	}
	
	if !checkbox.IsFocusable() {
		t.Error("CheckBox should be focusable")
	}
	
	// Test initial state
	if checkbox.Checked {
		t.Error("CheckBox should be unchecked initially")
	}
	
	// Test toggle
	result := checkbox.Toggle()
	if !checkbox.Checked {
		t.Error("CheckBox should be checked after toggle")
	}
	
	if result != "checked" {
		t.Errorf("Expected 'checked', got '%s'", result)
	}
	
	// Test toggle callback
	callbackCalled := false
	checkbox.OnToggle = func(checked bool) string {
		callbackCalled = true
		if checked {
			return "Enabled"
		}
		return "Disabled"
	}
	
	result = checkbox.Toggle()
	if !callbackCalled {
		t.Error("OnToggle callback should have been called")
	}
	
	if result != "Disabled" {
		t.Errorf("Expected 'Disabled', got '%s'", result)
	}
}

func TestLabel(t *testing.T) {
	label := NewLabel("Test Label")
	
	if label.GetName() != "Test Label" {
		t.Errorf("Expected name 'Test Label', got '%s'", label.GetName())
	}
	
	if label.GetRole() != RoleLabel {
		t.Errorf("Expected role 'label', got '%s'", label.GetRole())
	}
	
	if label.IsFocusable() {
		t.Error("Label should not be focusable")
	}
}

func TestGUI(t *testing.T) {
	gui := NewGUI()
	
	if gui.GetElementCount() != 0 {
		t.Errorf("Expected 0 elements, got %d", gui.GetElementCount())
	}
	
	// Add elements
	button := NewButton("Button")
	label := NewLabel("Label")
	listbox := NewListBox("List", []string{"A", "B", "C"})
	
	gui.AddElement(label)   // Not focusable
	gui.AddElement(button)  // Focusable
	gui.AddElement(listbox) // Focusable
	
	if gui.GetElementCount() != 3 {
		t.Errorf("Expected 3 elements, got %d", gui.GetElementCount())
	}
	
	// Test initial focus (should skip label and focus button)
	focused := gui.GetFocusedElement()
	if focused.GetName() != "Button" {
		t.Errorf("Expected focus on 'Button', got '%s'", focused.GetName())
	}
	
	// Test forward navigation
	description := gui.MoveFocusForward()
	if description == "" {
		t.Error("MoveFocusForward should return a description")
	}
	
	focused = gui.GetFocusedElement()
	if focused.GetName() != "List" {
		t.Errorf("Expected focus on 'List', got '%s'", focused.GetName())
	}
	
	// Test backward navigation
	description = gui.MoveFocusBackward()
	if description == "" {
		t.Error("MoveFocusBackward should return a description")
	}
	
	focused = gui.GetFocusedElement()
	if focused.GetName() != "Button" {
		t.Errorf("Expected focus on 'Button', got '%s'", focused.GetName())
	}
}

func TestGUIKeyHandling(t *testing.T) {
	gui := NewGUI()
	
	button := NewButton("Test")
	activated := false
	button.OnClick = func() string {
		activated = true
		return "Activated"
	}
	gui.AddElement(button)
	
	// Test Tab key (press)
	result := gui.HandleKey("tab", true)
	if result == "" {
		t.Error("Tab key should return a description")
	}
	
	// Test Tab key (release) - should be ignored
	result = gui.HandleKey("tab", false)
	if result != "" {
		t.Error("Key release should be ignored")
	}
	
	// Test Enter key to activate button
	result = gui.HandleKey("enter", true)
	if !activated {
		t.Error("Button should have been activated")
	}
	
	if result != "Activated" {
		t.Errorf("Expected 'Activated', got '%s'", result)
	}
}

func TestGUIWithCheckBox(t *testing.T) {
	gui := NewGUI()
	
	checkbox := NewCheckBox("Accept", false)
	gui.AddElement(checkbox)
	
	// Test Space key to toggle checkbox
	result := gui.HandleKey("space", true)
	if !checkbox.Checked {
		t.Error("CheckBox should be checked after Space key")
	}
	
	if result != "checked" {
		t.Errorf("Expected 'checked', got '%s'", result)
	}
}

func TestGUIWithListBox(t *testing.T) {
	gui := NewGUI()
	
	listbox := NewListBox("Options", []string{"A", "B", "C"})
	gui.AddElement(listbox)
	
	// Test Down arrow
	result := gui.HandleKey("downArrow", true)
	if result != "B" {
		t.Errorf("Expected 'B', got '%s'", result)
	}
	
	// Test Up arrow
	result = gui.HandleKey("upArrow", true)
	if result != "A" {
		t.Errorf("Expected 'A', got '%s'", result)
	}
}
