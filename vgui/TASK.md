# VGUI Enhancement Task List

This document outlines the enhancements requested for the vgui package to make it more feature-complete and production-ready.

## 1. Localization System

### Requirements
- [ ] Create a localization folder structure (`vgui/locales/`)
- [ ] Implement locale support with a `Locale` type (e.g., "en", "ru", "de")
- [ ] Translate GUI role names and messages into:
  - [ ] English (default)
  - [ ] Russian
  - [ ] German
- [ ] GUI initialization should accept a locale parameter
- [ ] All speech output should use localized strings

### Messages to Localize
- Element roles: "button", "listbox", "checkbox", "label"
- States: "checked", "not checked", "selected"
- Navigation messages: "Top of list", "Bottom of list", "No elements", "No focusable elements"
- Position indicators: "X of Y"

### Example Usage
```go
gui := vgui.NewGUI(vgui.WithLocale("ru")) // Russian interface
```

## 2. Ensure slog Logger Usage

### Requirements
- [ ] Audit all code to ensure slog.Logger is used consistently
- [ ] Add logging statements for important events:
  - [ ] Element activation
  - [ ] Focus changes
  - [ ] Key events processed
  - [ ] Locale loading
- [ ] Ensure logger is properly propagated through all components

## 3. Enhanced Enter Key Behavior

### Requirements
- [ ] Implement smart Enter key routing:
  - If a "default" button (OK button) exists → always activate it
  - If no default button → activate currently focused element
- [ ] Add `IsDefault` property to Button type
- [ ] Modify key handling logic to check for default button first
- [ ] Add tests for this behavior

### Example
```go
okButton := vgui.NewButton("OK")
okButton.IsDefault = true // Enter key always activates this
```

## 4. Dialog Mode with OK/Cancel Support

### Requirements
- [ ] Create `Dialog` type that wraps GUI
- [ ] Dialog configuration options:
  ```go
  type DialogConfig struct {
      HasOK     bool
      HasCancel bool
      HasYes    bool
      HasNo     bool
  }
  ```
- [ ] Auto-create standard buttons based on config
- [ ] Escape key activates Cancel button if present
- [ ] Enter key activates default button (OK or Yes)
- [ ] Add callback for dialog result

### Example Usage
```go
dialog := vgui.NewDialog(vgui.DialogConfig{
    HasOK:     true,
    HasCancel: true,
})
dialog.AddElement(vgui.NewLabel("Are you sure?"))
// OK and Cancel buttons automatically added
```

## 5. Yes/No Confirmation Dialog

### Requirements
- [ ] Create convenience function for Yes/No dialogs
- [ ] Simple API for confirmations
- [ ] Return boolean result via callback

### Example Usage
```go
confirm := vgui.NewConfirmDialog("Delete file?")
confirm.OnResult = func(confirmed bool) string {
    if confirmed {
        return "File deleted"
    }
    return "Cancelled"
}
```

## 6. Multi-Window Support

### Requirements
- [ ] Create `WindowManager` type to manage multiple GUIs/dialogs
- [ ] Support window stack (modal behavior)
- [ ] Key events route to active window only
- [ ] Window switching (Alt+Tab concept?)
- [ ] Each window has its own focus state

### Example Usage
```go
manager := vgui.NewWindowManager()
mainWindow := vgui.NewGUI()
dialogWindow := vgui.NewDialog(...)

manager.AddWindow("main", mainWindow)
manager.ShowModal("dialog", dialogWindow) // Blocks input to main
manager.CloseWindow("dialog")
```

## 7. Text Input Elements (TextBox/TextArea)

### Requirements
- [ ] Create `TextBox` element for single-line text input
- [ ] Create `TextArea` element for multi-line text input
- [ ] Implement text editing capabilities:
  - [ ] Character navigation (Left/Right arrow)
  - [ ] Word navigation (Ctrl+Left/Right)
  - [ ] Line navigation (Home/End, Up/Down for TextArea)
  - [ ] Text insertion and deletion
  - [ ] Selection support
- [ ] Screen reader announcements:
  - [ ] Announce characters when navigating (e.g., "a", "b", "c")
  - [ ] Announce "space" for spaces, "blank" for end of line or end of text or empty text
  - [ ] Announce words on Ctrl+Left/Right navigation
  - [ ] Announce cursor position
  - [ ] Announce selected text
- [ ] Clipboard operations (Ctrl+C, Ctrl+V, Ctrl+X)
- [ ] Undo/Redo support (Ctrl+Z, Ctrl+Y)

### Example Usage
```go
textBox := vgui.NewTextBox("Name", "")
textBox.OnChange = func(text string) string {
    return fmt.Sprintf("Text changed to: %s", text)
}

textArea := vgui.NewTextArea("Description", "")
textArea.MaxLines = 10
```

## 8. Hotkey Support

### Requirements
- [ ] Implement global hotkey system
- [ ] Support standard hotkeys:
  - [ ] Ctrl+S for Save
  - [ ] Ctrl+O for Open
  - [ ] Ctrl+N for New
  - [ ] Ctrl+Q for Quit
  - [ ] Ctrl+Z/Y for Undo/Redo
  - [ ] Ctrl+C/V/X for Clipboard
- [ ] Allow custom hotkey registration
- [ ] Hotkey conflict detection
- [ ] Hotkey help/list (Ctrl+H or F1)

### Example Usage
```go
gui.RegisterHotkey("ctrl+s", func() string {
    saveFile()
    return "File saved"
})

gui.RegisterHotkey("ctrl+o", func() string {
    openFile()
    return "Open file dialog"
})
```

## 9. Example Applications

### Requirements
- [ ] Create diverse, real-world example applications
- [ ] Each example should demonstrate different vgui features
- [ ] Examples should be well-documented and runnable

### Example 1: Text Editor (example_text_editor)
**Description**: A remote text editor that edits `editme.txt` file

**Features**:
- Open file on startup (or create if doesn't exist)
- TextArea for editing content
- Hotkeys:
  - Ctrl+S: Save file
  - Ctrl+Q: Quit (with confirmation if unsaved)
  - Ctrl+Z/Y: Undo/Redo
  - Ctrl+C/V/X: Clipboard operations
- Status bar showing: filename, line/column, character count
- Screen reader announces:
  - Characters when navigating
  - Words on Ctrl+Left/Right
  - "blank" for spaces
  - Cursor position
  - File saved confirmation

**Usage**:
```go
editor := vgui.NewTextEditor("editme.txt")
editor.OnSave = func(content string) error {
    return os.WriteFile("editme.txt", []byte(content), 0644)
}
handler := vgui.NewHandler(remote, editor.GetGUI(), logger)
handler.Start()
```

### Example 2: Todo List Manager (example_todo)
**Description**: Interactive todo list with add/edit/delete operations

**Features**:
- ListBox showing all todos
- Buttons: Add, Edit, Delete, Mark Complete
- Dialog for adding new todo (TextBox + OK/Cancel)
- Confirmation dialog for delete
- Hotkeys:
  - Ctrl+N: New todo
  - Delete: Delete selected todo
  - Space: Toggle complete status
- Persistent storage (JSON file)

### Example 3: Configuration Manager (example_config)
**Description**: System configuration interface

**Features**:
- Multiple tabs/windows for different config sections
- CheckBoxes for boolean options
- ListBoxes for selection options
- TextBoxes for text values
- Apply/Cancel/OK buttons
- Validation with error messages
- Localization support (demonstrate Russian/German)

### Example 4: Interactive Game (example_game)
**Description**: Simple text-based game (e.g., Number Guessing)

**Features**:
- TextBox for input
- Game state announcements
- Score tracking
- Play again dialog
- Sound effects via beeps

### Example 5: Remote Calculator (example_calculator)
**Description**: Accessible calculator interface

**Features**:
- TextBox for display
- Buttons for digits 0-9 and operators
- Hotkeys for keyboard input
- History list
- Copy result to clipboard

## 10. Screen Reader Behavior Testing

### Requirements
- [ ] Create comprehensive test suite for screen reader behavior
- [ ] Test all text navigation scenarios
- [ ] Verify speech output for all interactions
- [ ] Test with different element types

### Test Scenarios for TextBox/TextArea

#### Character Navigation
- [ ] Left arrow announces previous character
- [ ] Right arrow announces next character
- [ ] Space character announced as "blank"
- [ ] Special characters announced correctly (e.g., "period", "comma")
- [ ] Beginning/end of text announced

#### Word Navigation
- [ ] Ctrl+Left moves to previous word and announces it
- [ ] Ctrl+Right moves to next word and announces it
- [ ] Words separated by spaces correctly identified
- [ ] Punctuation handling in word boundaries

#### Line Navigation (TextArea)
- [ ] Up/Down arrow moves between lines
- [ ] Home/End moves to line start/end
- [ ] Current line announced when moving between lines
- [ ] Line number announced

#### Text Editing
- [ ] Character insertion announced
- [ ] Character deletion announced (Backspace/Delete)
- [ ] Word deletion announced (Ctrl+Backspace/Delete)
- [ ] Paste operation announced with pasted text
- [ ] Undo/Redo announced with action description

#### Selection
- [ ] Shift+Arrow announces selected text
- [ ] Ctrl+A announces "all selected"
- [ ] Selection cleared announcement
- [ ] Selected text read on request

### Integration Test Example
```go
func TestTextBoxScreenReaderBehavior(t *testing.T) {
    gui := vgui.NewGUI()
    textBox := vgui.NewTextBox("Test", "Hello World")
    gui.AddElement(textBox)
    
    // Test: Right arrow from 'H' should announce 'e'
    textBox.SetCursorPosition(0)
    speech := gui.HandleKey("rightArrow", true)
    assert.Equal(t, "e", speech)
    
    // Test: Space should be announced as "blank"
    textBox.SetCursorPosition(5) // At space after "Hello"
    speech = gui.HandleKey("rightArrow", true)
    assert.Equal(t, "blank", speech)
    
    // Test: Ctrl+Right should announce next word
    textBox.SetCursorPosition(0)
    speech = gui.HandleKeyWithModifiers("rightArrow", []string{"ctrl"}, true)
    assert.Equal(t, "World", speech)
}
```

## 11. Testing Requirements

### Test Coverage Needed
- [ ] Localization tests (all supported languages)
- [ ] Enter key behavior with/without default button
- [ ] Escape key for cancel
- [ ] Dialog creation and button auto-generation
- [ ] Yes/No confirmation flow
- [ ] Multi-window focus management
- [ ] Window stack behavior
- [ ] TextBox character/word navigation
- [ ] TextArea line navigation
- [ ] Hotkey registration and execution
- [ ] Hotkey conflicts
- [ ] Screen reader announcements for all interactions

### Integration Tests
- [ ] Complete dialog workflow
- [ ] Window switching
- [ ] Localized output verification
- [ ] Text editor workflow (open, edit, save)
- [ ] Todo list operations (CRUD)
- [ ] Configuration manager with validation

## Implementation Notes

### Breaking Changes
- GUI initialization may need to accept options (locale, default settings)
- Handler may need updates to support window manager
- Key handling extended for modifier key combinations (Ctrl+Key)

### Backward Compatibility
- Existing code should continue to work
- New features opt-in via configuration
- TextBox/TextArea are new elements, won't affect existing code

### Documentation Updates
- [ ] Update vgui/README.md with new features
- [ ] Add examples for each new feature
- [ ] Document localization system
- [ ] Add multi-window examples
- [ ] Document TextBox/TextArea usage
- [ ] Document hotkey system
- [ ] Create README for each example application

### Example Directory Structure
```
example_text_editor/
  ├── main.go
  ├── editme.txt
  └── README.md

example_todo/
  ├── main.go
  ├── todos.json
  └── README.md

example_config/
  ├── main.go
  ├── config.json
  └── README.md

example_game/
  ├── main.go
  └── README.md

example_calculator/
  ├── main.go
  └── README.md
```

## Suggested Approach

1. **Phase 1**: Localization system (foundation for other features)
2. **Phase 2**: Dialog mode and standard buttons
3. **Phase 3**: Enhanced key behavior (Enter, Escape)
4. **Phase 4**: Yes/No confirmations
5. **Phase 5**: Hotkey system
6. **Phase 6**: TextBox/TextArea elements with screen reader support
7. **Phase 7**: Multi-window support
8. **Phase 8**: Example applications
9. **Phase 9**: Comprehensive testing

Each phase should include:
- Implementation
- Unit tests
- Documentation updates
- Example updates (where applicable)

## Estimated Complexity

- **Localization**: Medium (2-3 hours)
- **Dialog Mode**: Medium (2-3 hours)
- **Enhanced Keys**: Low (1 hour)
- **Yes/No Dialogs**: Low (1 hour)
- **Hotkey System**: Medium (2-3 hours)
- **TextBox/TextArea**: High (6-8 hours) - Complex screen reader behavior
- **Multi-Window**: High (4-6 hours)
- **Example Applications**: High (6-8 hours) - 5 comprehensive examples
- **Testing**: High (4-6 hours) - Comprehensive test suite

**Total**: ~30-40 hours of work

## Priority Order

### High Priority (Core Functionality)
1. TextBox/TextArea elements
2. Hotkey system
3. Screen reader behavior testing
4. Text editor example

### Medium Priority (Enhanced UX)
1. Dialog mode with OK/Cancel
2. Enhanced Enter/Escape behavior
3. Localization system
4. Additional examples (todo, config)

### Lower Priority (Advanced Features)
1. Multi-window support
2. Game/calculator examples
3. Advanced text features (undo/redo)

## Decision

Given the scope of these enhancements, this should be implemented as a **new pull request** to keep changes organized and reviewable.

## Next Steps

1. Close current PR or merge it as foundation
2. Create new branch for enhancements
3. Implement features incrementally with tests
4. Submit new PR with reference to this task list
