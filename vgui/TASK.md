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

## 7. Testing Requirements

### Test Coverage Needed
- [ ] Localization tests (all supported languages)
- [ ] Enter key behavior with/without default button
- [ ] Escape key for cancel
- [ ] Dialog creation and button auto-generation
- [ ] Yes/No confirmation flow
- [ ] Multi-window focus management
- [ ] Window stack behavior

### Integration Tests
- [ ] Complete dialog workflow
- [ ] Window switching
- [ ] Localized output verification

## Implementation Notes

### Breaking Changes
- GUI initialization may need to accept options (locale, default settings)
- Handler may need updates to support window manager

### Backward Compatibility
- Existing code should continue to work
- New features opt-in via configuration

### Documentation Updates
- [ ] Update vgui/README.md with new features
- [ ] Add examples for each new feature
- [ ] Document localization system
- [ ] Add multi-window examples

## Suggested Approach

1. **Phase 1**: Localization system (foundation for other features)
2. **Phase 2**: Dialog mode and standard buttons
3. **Phase 3**: Enhanced key behavior (Enter, Escape)
4. **Phase 4**: Yes/No confirmations
5. **Phase 5**: Multi-window support
6. **Phase 6**: Comprehensive testing

Each phase should include:
- Implementation
- Unit tests
- Documentation updates
- Example updates

## Estimated Complexity

- **Localization**: Medium (2-3 hours)
- **Dialog Mode**: Medium (2-3 hours)
- **Enhanced Keys**: Low (1 hour)
- **Yes/No Dialogs**: Low (1 hour)
- **Multi-Window**: High (4-6 hours)
- **Testing**: Medium (2-3 hours)

**Total**: ~15-20 hours of work

## Decision

Given the scope of these enhancements, this should be implemented as a **new pull request** to keep changes organized and reviewable.

## Next Steps

1. Close current PR or merge it as foundation
2. Create new branch for enhancements
3. Implement features incrementally with tests
4. Submit new PR with reference to this task list
