package vgui

import "fmt"

// Button represents a virtual button element
type Button struct {
	BaseElement
	OnClick   func() string // Callback function when button is clicked
	IsDefault bool          // If true, Enter key activates this button
}

// NewButton creates a new button with the given name
func NewButton(name string) *Button {
	return &Button{
		BaseElement: BaseElement{
			Name:      name,
			role:      RoleButton,
			focusable: true,
		},
	}
}

// OnActivate handles button activation (e.g., Enter key)
func (b *Button) OnActivate() string {
	if b.OnClick != nil {
		return b.OnClick()
	}
	return b.Name + " pressed"
}

// ListBox represents a virtual listbox element with selectable items
type ListBox struct {
	BaseElement
	Items         []string
	SelectedIndex int
}

// NewListBox creates a new listbox with the given name and items
func NewListBox(name string, items []string) *ListBox {
	return &ListBox{
		BaseElement: BaseElement{
			Name:      name,
			role:      RoleListBox,
			focusable: true,
		},
		Items:         items,
		SelectedIndex: 0,
	}
}

// GetDescription returns the description including the current selected item
func (l *ListBox) GetDescription() string {
	if len(l.Items) == 0 {
		emptyMsg := "empty"
		if l.localizer != nil {
			emptyMsg = l.localizer.T("empty")
		}
		roleStr := string(l.role)
		if l.localizer != nil {
			roleStr = l.localizer.T(string(l.role))
		}
		return l.Name + ", " + roleStr + ", " + emptyMsg
	}
	selectedItem := l.Items[l.SelectedIndex]
	selectedStr := "selected"
	ofStr := "of"
	roleStr := string(l.role)
	if l.localizer != nil {
		selectedStr = l.localizer.T("selected")
		ofStr = l.localizer.T("of")
		roleStr = l.localizer.T(string(l.role))
	}
	return fmt.Sprintf("%s, %s, %s %s, %d %s %d", l.Name, roleStr, selectedItem, selectedStr, l.SelectedIndex+1, ofStr, len(l.Items))
}

// MoveUp moves the selection up in the listbox
func (l *ListBox) MoveUp() string {
	if l.SelectedIndex > 0 {
		l.SelectedIndex--
		return l.Items[l.SelectedIndex]
	}
	if l.localizer != nil {
		return l.localizer.T("top of list")
	}
	return "Top of list"
}

// MoveDown moves the selection down in the listbox
func (l *ListBox) MoveDown() string {
	if l.SelectedIndex < len(l.Items)-1 {
		l.SelectedIndex++
		return l.Items[l.SelectedIndex]
	}
	if l.localizer != nil {
		return l.localizer.T("bottom of list")
	}
	return "Bottom of list"
}

// GetSelectedItem returns the currently selected item
func (l *ListBox) GetSelectedItem() string {
	if len(l.Items) == 0 {
		return ""
	}
	return l.Items[l.SelectedIndex]
}

// OnActivate returns the selected item when activated
func (l *ListBox) OnActivate() string {
	if len(l.Items) == 0 {
		return "No item selected"
	}
	return l.Items[l.SelectedIndex] + " selected"
}

// CheckBox represents a virtual checkbox element
type CheckBox struct {
	BaseElement
	Checked  bool
	OnToggle func(checked bool) string // Callback when checkbox is toggled
}

// NewCheckBox creates a new checkbox with the given name
func NewCheckBox(name string, checked bool) *CheckBox {
	return &CheckBox{
		BaseElement: BaseElement{
			Name:      name,
			role:      RoleCheckBox,
			focusable: true,
		},
		Checked: checked,
	}
}

// GetDescription returns the description including the checked state
func (c *CheckBox) GetDescription() string {
	stateKey := "not checked"
	if c.Checked {
		stateKey = "checked"
	}
	state := stateKey
	if c.localizer != nil {
		state = c.localizer.T(stateKey)
	}
	roleStr := string(c.role)
	if c.localizer != nil {
		roleStr = c.localizer.T(string(c.role))
	}
	return c.Name + ", " + roleStr + ", " + state
}

// Toggle toggles the checkbox state
func (c *CheckBox) Toggle() string {
	c.Checked = !c.Checked
	stateKey := "not checked"
	if c.Checked {
		stateKey = "checked"
	}
	state := stateKey
	if c.localizer != nil {
		state = c.localizer.T(stateKey)
	}
	
	if c.OnToggle != nil {
		return c.OnToggle(c.Checked)
	}
	return state
}

// OnActivate toggles the checkbox when activated
func (c *CheckBox) OnActivate() string {
	return c.Toggle()
}

// OnStateChange returns the current state
func (c *CheckBox) OnStateChange() string {
	stateKey := "not checked"
	if c.Checked {
		stateKey = "checked"
	}
	state := stateKey
	if c.localizer != nil {
		state = c.localizer.T(stateKey)
	}
	return state
}

// Label represents a virtual label element (non-focusable)
type Label struct {
	BaseElement
}

// NewLabel creates a new label with the given text
func NewLabel(text string) *Label {
	return &Label{
		BaseElement: BaseElement{
			Name:      text,
			role:      RoleLabel,
			focusable: false,
		},
	}
}
