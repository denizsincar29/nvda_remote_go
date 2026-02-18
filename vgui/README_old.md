# Virtual GUI (vgui) Package

The `vgui` package provides a virtual GUI framework for NVDA remote clients. It allows you to create accessible remote interfaces that can be navigated using keyboard commands and spoken back to the user through the NVDA remote protocol.

## Overview

The vgui package enables you to create virtual GUI elements (buttons, listboxes, checkboxes, labels) that exist only in memory but provide a full accessible interface to remote NVDA users. This is perfect for creating:

- Remote configuration interfaces
- Interactive menus
- Forms and surveys
- Games with accessible interfaces
- Any remote application that needs user interaction

## Key Features

- **Virtual GUI Elements**: Create buttons, listboxes, checkboxes, and labels
- **Keyboard Navigation**: Full Tab/Shift+Tab navigation support
- **Speech Output**: Automatic speech output for all interactions
- **Focus Management**: Intelligent focus handling for navigation
- **Event Callbacks**: Custom callbacks for element activation
- **Thread-Safe**: All operations are protected with mutexes

## Requirements

The NVDA remote client **MUST** be connected in **slave mode** for the vgui to work properly. This is because the slave client receives key press events from the controller client.

## Basic Usage

```go
package main

import (
    "log/slog"
    "github.com/denizsincar29/nvda_remote_go"
    "github.com/denizsincar29/nvda_remote_go/vgui"
)

func main() {
    logger := slog.Default()
    
    // Create NVDA remote client in SLAVE mode (required!)
    remote, err := nvda_remote_go.NewClient("nvdaremote.ru", "6837", "my_key", "slave", logger)
    if err != nil {
        panic(err)
    }
    defer remote.Close()
    
    // Create a virtual GUI
    gui := vgui.NewGUI()
    
    // Add elements
    gui.AddElement(vgui.NewLabel("Welcome!"))
    gui.AddElement(vgui.NewButton("OK"))
    
    // Create and start the handler
    handler := vgui.NewHandler(remote, gui, logger)
    handler.Start()
    
    // Keep running
    select {}
}
```

## GUI Elements

### Button

A clickable button that can be activated with Enter or Space key.

```go
button := vgui.NewButton("Submit")
button.OnClick = func() string {
    return "Form submitted successfully"
}
gui.AddElement(button)
```

### ListBox

A listbox with selectable items, navigable with Up/Down arrow keys.

```go
listbox := vgui.NewListBox("Choose option", []string{
    "Option 1",
    "Option 2", 
    "Option 3",
})
gui.AddElement(listbox)

// Get selected item later
selected := listbox.GetSelectedItem()
```

### CheckBox

A checkbox that can be toggled with Space or Enter key.

```go
checkbox := vgui.NewCheckBox("Accept terms", false)
checkbox.OnToggle = func(checked bool) string {
    if checked {
        return "Terms accepted"
    }
    return "Terms not accepted"
}
gui.AddElement(checkbox)
```

### Label

A non-focusable label for displaying text.

```go
label := vgui.NewLabel("Instructions: Use Tab to navigate")
gui.AddElement(label)
```

## Keyboard Navigation

The vgui package handles the following keyboard commands automatically:

- **Tab**: Move focus to the next focusable element
- **Shift+Tab**: Move focus to the previous focusable element
- **Enter**: Activate the focused element
- **Space**: Activate the focused element (also toggles checkboxes)
- **Up Arrow**: Navigate up in listboxes
- **Down Arrow**: Navigate down in listboxes

## Example: Complete Form

```go
package main

import (
    "fmt"
    "github.com/denizsincar29/nvda_remote_go/vgui"
)

func createForm(gui *vgui.GUI) {
    // Welcome message
    gui.AddElement(vgui.NewLabel("Registration Form"))
    
    // Gender selection
    genderList := vgui.NewListBox("Gender", []string{
        "Male", "Female", "Other", "Prefer not to say",
    })
    gui.AddElement(genderList)
    
    // Age range
    ageList := vgui.NewListBox("Age Range", []string{
        "Under 18", "18-25", "26-35", "36-45", "46-55", "Over 55",
    })
    gui.AddElement(ageList)
    
    // Newsletter subscription
    newsletter := vgui.NewCheckBox("Subscribe to newsletter", false)
    gui.AddElement(newsletter)
    
    // Submit button
    submitBtn := vgui.NewButton("Submit")
    submitBtn.OnClick = func() string {
        return fmt.Sprintf("Submitted: Gender=%s, Age=%s, Newsletter=%v",
            genderList.GetSelectedItem(),
            ageList.GetSelectedItem(),
            newsletter.Checked,
        )
    }
    gui.AddElement(submitBtn)
    
    // Cancel button
    cancelBtn := vgui.NewButton("Cancel")
    cancelBtn.OnClick = func() string {
        return "Form cancelled"
    }
    gui.AddElement(cancelBtn)
}
```

## Speech Output

All interactions with the GUI automatically generate speech output that is sent to the NVDA remote client:

- When an element receives focus: Speaks the element's name and role (e.g., "Gender, listbox, Male selected, 1 of 4")
- When navigating in a listbox: Speaks the current item
- When toggling a checkbox: Speaks the new state
- When activating a button: Speaks the custom callback response

## Advanced Usage

### Custom Element Behavior

You can customize element behavior with callbacks:

```go
button := vgui.NewButton("Custom")
button.OnClick = func() string {
    // Custom logic here
    doSomething()
    return "Custom action completed"
}
```

### Accessing GUI State

```go
// Get currently focused element
element := gui.GetFocusedElement()

// Get element count
count := gui.GetElementCount()

// Manually trigger speech for focused element
text := gui.SpeakFocusedElement()
```

### Managing the Handler

```go
handler := vgui.NewHandler(remote, gui, logger)

// Start handling
handler.Start()

// Check if active
if handler.IsActive() {
    // Handler is running
}

// Stop handling
handler.Stop()

// Access underlying components
gui := handler.GetGUI()
client := handler.GetClient()
```

## Thread Safety

The vgui package is designed to be thread-safe. All operations on the GUI are protected with read-write mutexes, allowing safe concurrent access from multiple goroutines.

## Limitations

1. The client must be in **slave mode** (cannot be controller)
2. Labels are not focusable and are skipped during navigation
3. Only keyboard navigation is supported (no mouse events)
4. Elements cannot be dynamically removed (only added)

## Example Project

See `example_vgui/main.go` for a complete working example that demonstrates all features of the vgui package.

## API Reference

For detailed API documentation, see the godoc comments in the source files:

- `element.go` - Base element interface and types
- `elements.go` - Concrete element implementations  
- `gui.go` - GUI manager and navigation
- `handler.go` - NVDA remote integration
