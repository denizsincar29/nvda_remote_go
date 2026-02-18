// Package vgui provides a virtual GUI framework for NVDA remote clients.
// It allows creating virtual GUI elements that can be navigated via keyboard
// and spoken back to the user through the NVDA remote protocol.
package vgui

// Role represents the role/type of a GUI element (e.g., button, listbox, checkbox)
type Role string

const (
	RoleButton   Role = "button"
	RoleListBox  Role = "listbox"
	RoleCheckBox Role = "checkbox"
	RoleLabel    Role = "label"
)

// Element is the interface that all virtual GUI elements must implement
type Element interface {
	// GetName returns the name/label of the element
	GetName() string
	
	// GetRole returns the role of the element
	GetRole() Role
	
	// GetDescription returns a description suitable for speech output
	GetDescription() string
	
	// IsFocusable returns true if the element can receive focus
	IsFocusable() bool
	
	// OnActivate is called when the element is activated (e.g., Enter key pressed)
	OnActivate() string
	
	// OnStateChange is called when the element's state changes
	OnStateChange() string
}

// BaseElement provides a basic implementation of common element functionality
type BaseElement struct {
	Name        string
	Description string
	role        Role
	focusable   bool
}

func (b *BaseElement) GetName() string {
	return b.Name
}

func (b *BaseElement) GetRole() Role {
	return b.role
}

func (b *BaseElement) GetDescription() string {
	if b.Description != "" {
		return b.Description
	}
	return b.Name + ", " + string(b.role)
}

func (b *BaseElement) IsFocusable() bool {
	return b.focusable
}

func (b *BaseElement) OnActivate() string {
	return ""
}

func (b *BaseElement) OnStateChange() string {
	return ""
}
