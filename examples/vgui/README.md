# Virtual GUI (VGUI) Unified Examples

This is a unified launcher for all VGUI examples, demonstrating the complete virtual GUI framework for NVDA Remote Go.

## What is VGUI?

VGUI (Virtual GUI) is a framework that creates accessible virtual graphical user interfaces through NVDA Remote. It provides screen reader support for interactive applications without requiring a visual interface.

## Running the Examples

From the repository root:
```bash
go run ./examples/vgui
```

Or from this directory:
```bash
go run .
```

## Available Examples

All examples are accessible from the unified menu:

### 1. Simple Calculator
Basic arithmetic calculator with:
- Number input (0-9)
- Operations (+, -, *, /)
- Clear function
- History tracking

### 2. Simple Form
Demonstrates form controls:
- Text input boxes
- List boxes (gender, age range)
- Checkboxes (newsletter subscription)
- Submit/Cancel buttons

### 3. Number Guessing Game
Interactive game featuring:
- Guess a number between 1-100
- 7 attempts per game
- Score tracking
- Hint system
- Audio feedback

### 4. Text Editor
Simple text file editor with:
- Multi-line text editing
- Arrow key navigation
- Save functionality (Ctrl+S)
- File modification tracking

### 5. Todo List Manager
Todo application with:
- Add new todos
- Toggle completion status
- Delete todos
- Persistent storage (todos.json)

## Navigation

- **Tab**: Move forward through elements
- **Shift+Tab**: Move backward through elements
- **Enter**: Activate buttons
- **Space**: Toggle checkboxes
- **Arrow Keys**: Navigate lists and text
- **Escape**: Return to main menu (from sub-screens)
- **Alt+F4**: Close current window
- **Win+D**: Go to desktop view
- **Alt+Shift**: Switch keyboard layout (US, Russian, German)

## Window Management

The unified menu supports multiple windows:
- Each example opens in its own window
- Use Alt+F4 to close the current window and return to the previous
- Use Win+D to view all open windows on the desktop
- Window stack tracks navigation history

## Features Demonstrated

- Multiple window management with stack
- Text input with keyboard layout support
- List boxes and checkboxes
- Hotkey system (Escape, Ctrl+S, etc.)
- Speech interruption for better accessibility
- Localization support
- Default button behavior (Enter key)

## Configuration

Before running, configure your NVDA Remote credentials using the setup script from the root directory:
```bash
./setup.sh
```

Or create a `.env` file in the root directory with:
```
NVDA_REMOTE_KEY=your_key_here
NVDA_REMOTE_HOST=nvdaremote.ru
NVDA_REMOTE_PORT=6837
```

## Development

The unified menu is implemented in `unified_menu/main.go` and consolidates all previous separate examples into a single application for easier access and better user experience.
