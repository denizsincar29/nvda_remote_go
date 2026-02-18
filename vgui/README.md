# Virtual GUI (vgui) Package

The `vgui` package provides a comprehensive virtual GUI framework for NVDA remote clients. It allows you to create fully accessible remote interfaces that can be navigated using keyboard commands and spoken back to the user through the NVDA remote protocol.

## Overview

The vgui package enables you to create virtual GUI elements that exist only in memory but provide a complete accessible interface to remote NVDA users. This is perfect for creating:

- Remote text editors and file managers
- Interactive forms and surveys  
- Configuration interfaces
- Todo lists and task managers
- Accessible games
- Calculators and utilities
- Any remote application that needs user interaction

## Key Features

### Core Features
- **Rich GUI Elements**: Buttons, ListBoxes, CheckBoxes, Labels, TextBoxes, TextAreas
- **Keyboard Navigation**: Full Tab/Shift+Tab navigation, arrow key navigation
- **Speech Output**: Automatic screen reader announcements for all interactions
- **Focus Management**: Intelligent focus handling and navigation
- **Event Callbacks**: Custom callbacks for element activation and state changes
- **Thread-Safe**: All operations are protected with mutexes

### Advanced Features
- **Localization**: Support for multiple languages (English, Russian, German)
- **Hotkey System**: Register global hotkeys (Ctrl+S, Ctrl+Q, etc.)
- **Dialog System**: Standard dialogs with OK/Cancel/Yes/No buttons
- **Default Buttons**: Enter key activates default button
- **Multi-Window Support**: Window manager for modal dialogs
- **Text Input**: Full text editing with character, word, and line navigation
- **Screen Reader Integration**: Rich announcements for text navigation

## Requirements

The NVDA remote client **MUST** be connected in **slave mode** for the vgui to work properly. This is because the slave client receives key press events from the controller client.

## Quick Start

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
    
    // Create a virtual GUI with options
    gui := vgui.NewGUI(
        vgui.WithLocale(vgui.LocaleEnglish),
        vgui.WithLogger(logger),
    )
    
    // Add elements
    gui.AddElement(vgui.NewLabel("Welcome!"))
    
    button := vgui.NewButton("OK")
    button.IsDefault = true // Enter key will activate this
    button.OnClick = func() string {
        return "Button clicked!"
    }
    gui.AddElement(button)
    
    // Register hotkeys
    gui.RegisterHotkey("ctrl+q", func() string {
        return "Quit requested"
    })
    
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
button.IsDefault = true // Makes this the default button
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

### TextBox

A single-line text input element with full text editing capabilities.

```go
textbox := vgui.NewTextBox("Name", "Initial value")
textbox.OnChange = func(text string) string {
    return "Text changed"
}
gui.AddElement(textbox)
```

**Features:**
- Character-by-character navigation (Left/Right arrows)
- Word navigation (Ctrl+Left/Right)
- Home/End keys for start/end
- Backspace/Delete for editing
- Character insertion
- Screen reader announces: characters, "blank" for spaces, words on Ctrl+arrows

### TextArea

A multi-line text input element for editing larger text.

```go
textarea := vgui.NewTextArea("Content", "Initial text\nLine 2")
textarea.OnChange = func(text string) string {
    return "Content updated"
}
gui.AddElement(textarea)
```

**Features:**
- All TextBox features
- Line navigation (Up/Down arrows)
- Line start/end (Home/End)
- Screen reader announces: line content, cursor position

## Localization

The vgui package supports multiple languages for all UI strings.

```go
// Create GUI with Russian locale
gui := vgui.NewGUI(vgui.WithLocale(vgui.LocaleRussian))

// Or German
gui := vgui.NewGUI(vgui.WithLocale(vgui.LocaleGerman))
```

**Supported Locales:**
- `LocaleEnglish` (default)
- `LocaleRussian`
- `LocaleGerman`

All role names, states, and navigation messages are automatically translated.

## Dialogs

### Standard Dialog

Create dialogs with standard OK/Cancel/Yes/No buttons.

```go
config := vgui.DialogConfig{
    HasOK:     true,
    HasCancel: true,
}

dialog := vgui.NewDialog(config, vgui.WithLocale(vgui.LocaleEnglish))
dialog.AddElement(vgui.NewLabel("Are you sure?"))
dialog.AddStandardButtons()

dialog.OnResult = func(result string) string {
    if result == "ok" {
        return "Confirmed"
    }
    return "Cancelled"
}

// Escape key activates Cancel button
handler := vgui.NewHandler(remote, dialog.GUI, logger)
handler.Start()
```

### Confirmation Dialog

Quick Yes/No confirmation dialogs.

```go
dialog := vgui.NewConfirmDialog("Delete file?")
dialog.SetConfirmCallback(func(confirmed bool) string {
    if confirmed {
        return "File deleted"
    }
    return "Cancelled"
})
```

## Hotkey System

Register global hotkeys for quick access to functionality.

```go
// Save hotkey
gui.RegisterHotkey("ctrl+s", func() string {
    saveFile()
    return "File saved"
})

// Quit hotkey
gui.RegisterHotkey("ctrl+q", func() string {
    if hasUnsavedChanges {
        return "Save first or confirm quit"
    }
    os.Exit(0)
    return "Quitting"
})

// Check for conflicts
err := gui.RegisterHotkey("ctrl+s", anotherCallback)
// Returns error if already registered
```

**Supported Modifiers:**
- `ctrl+key` or `control+key`
- `shift+key`
- `alt+key`
- Combinations like `ctrl+shift+key`

## Multi-Window Support

Manage multiple windows and modal dialogs.

```go
wm := vgui.NewWindowManager(logger)

// Add main window
mainGUI := vgui.NewGUI()
wm.AddWindow("main", mainGUI)

// Show modal dialog
dialogGUI := vgui.NewDialog(config)
wm.ShowModal("dialog", dialogGUI.GUI)

// Close dialog
wm.CloseWindow("dialog")

// Route keys to active window
wm.HandleKey("tab", true)
```

## Keyboard Navigation

The vgui package handles the following keyboard commands automatically:

**Global:**
- **Tab**: Move focus to the next focusable element
- **Shift+Tab**: Move focus to the previous focusable element
- **Enter**: Activate focused element (or default button if set)
- **Escape**: Activate Cancel button in dialogs

**Element-Specific:**
- **Space**: Toggle CheckBox, activate Button
- **Up/Down Arrow**: Navigate ListBox items or TextArea lines
- **Left/Right Arrow**: Navigate TextBox/TextArea characters
- **Ctrl+Left/Right**: Navigate TextBox/TextArea words
- **Home/End**: Start/end of line in TextBox/TextArea
- **Backspace/Delete**: Delete characters in TextBox/TextArea

**Hotkeys:**
- Any registered hotkeys (Ctrl+S, Ctrl+Q, etc.)

## Screen Reader Behavior

The vgui package provides rich screen reader feedback:

### Button/CheckBox/Label
- Announces name, role, and state
- Example: "Submit, button" or "Accept terms, checkbox, checked"

### ListBox
- Announces selected item, position
- Example: "Option 2, 2 of 5"
- Navigation: "Top of list", "Bottom of list"

### TextBox/TextArea
- **Character navigation**: Announces each character
- **Spaces**: Announced as "blank"
- **Word navigation**: Announces whole words
- **Line navigation**: Announces line content
- **Boundaries**: "beginning of text", "end of text"

## Example Applications

The package includes several complete example applications:

### Text Editor (`examples/vgui/text_editor`)
- Multi-line text editing with TextArea
- File save/load operations
- Ctrl+S to save, Ctrl+Q to quit
- Status bar with line/column info

### Todo List (`examples/vgui/todo`)
- Task management with ListBox
- Add, toggle, delete operations
- JSON persistence
- Keyboard shortcuts

### Calculator (`examples/vgui/calculator`)
- Number and operator buttons
- Keyboard input support
- Calculation history
- Default button for equals

### Number Guessing Game (`examples/vgui/game`)
- Interactive gameplay
- Audio feedback with beeps
- Hint system
- Score tracking

## Advanced Usage

### Custom Element Behavior

```go
button := vgui.NewButton("Custom")
button.OnClick = func() string {
    // Custom logic here
    result := doSomething()
    return fmt.Sprintf("Processed: %s", result)
}
```

### Accessing GUI State

```go
// Get currently focused element
element := gui.GetFocusedElement()

// Get element count
count := gui.GetElementCount()

// Get all elements
elements := gui.GetElements()

// Get default button
defaultBtn := gui.GetDefaultButton()

// Get registered hotkeys
hotkeys := gui.GetRegisteredHotkeys()
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

## Best Practices

1. **Always use slave mode** for the NVDA remote client
2. **Set default buttons** for forms and dialogs
3. **Provide clear labels** for all elements
4. **Use hotkeys** for frequently used actions
5. **Announce meaningful results** in callbacks
6. **Handle empty states** in ListBoxes and TextBoxes
7. **Localize** your application if targeting international users
8. **Test with screen readers** to ensure good UX

## Limitations

1. Client must be in **slave mode** (cannot be controller)
2. Labels are not focusable and are skipped during navigation
3. Only keyboard navigation is supported (no mouse events)
4. Elements cannot be dynamically removed (only added)
5. Clipboard operations require OS-specific implementations
6. Text selection is not yet implemented

## Complete Example

See `examples/vgui/simple_form/main.go` and other examples for complete working demonstrations of all features.

## API Reference

For detailed API documentation, see the godoc comments in the source files:

- `element.go` - Base element interface and types
- `elements.go` - Concrete element implementations (Button, ListBox, CheckBox, Label)
- `textbox.go` - TextBox and TextArea implementations
- `dialog.go` - Dialog, ConfirmDialog, and WindowManager
- `locale.go` - Localization system
- `gui.go` - GUI manager, navigation, and hotkeys
- `handler.go` - NVDA remote integration

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`go test ./vgui`)
- Code follows Go best practices
- New features include tests
- Documentation is updated
