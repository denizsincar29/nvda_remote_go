# Unified Menu Demo

This is a demonstration of a multi-window VGUI application that combines multiple examples into a single menu-driven interface.

## Features

- **Main Menu**: Navigate between different examples
- **Simple Calculator**: Perform basic arithmetic operations
- **Simple Form**: Fill out a form with text input, list boxes, and checkboxes
- **About Screen**: Learn about the application features

## How to Run

```bash
cd examples/vgui/unified_menu
go run .
```

## Navigation

- **Tab**: Move forward through elements
- **Shift+Tab**: Move backward through elements
- **Enter**: Activate buttons
- **Escape**: Return to main menu (from sub-screens)
- **Alt+Shift**: Switch keyboard layout (US, Russian, German)
- **Ctrl+A**: Select all text in textboxes

## Keyboard Layouts

The application supports multiple keyboard layouts:
- **US English** (QWERTY)
- **Russian** (ЙЦУКЕН)
- **German** (QWERTZ)

Use Alt+Shift to cycle through available layouts. The layout affects how Shift+key combinations produce characters (e.g., Shift+1 produces "!" in US and Russian layouts but "!" in German layout; Shift+3 produces "#" in US layout but "№" in Russian layout).

## Multi-Window Design

This example demonstrates how to create a multi-window application with VGUI:
1. Each "window" is a separate GUI instance
2. Switching windows recreates the handler with the new GUI
3. Navigation between windows is seamless with back buttons and hotkeys

This pattern can be extended to create complex applications with multiple screens, dialogs, and navigation flows.
