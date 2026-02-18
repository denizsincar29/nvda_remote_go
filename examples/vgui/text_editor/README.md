# Remote Text Editor Example

This example demonstrates a fully functional remote text editor using the vgui package.

## Features

- **Text Editing**: Edit text files remotely with full accessibility
- **Text Navigation**: 
  - Arrow keys for character-by-character navigation
  - Ctrl+Left/Right for word-by-word navigation
  - Home/End for line start/end
  - Up/Down arrows for line navigation (in TextArea)
- **Screen Reader Support**:
  - Characters announced when navigating
  - "blank" announced for spaces
  - Words announced on word navigation
  - Line content announced on line navigation
- **File Operations**:
  - Ctrl+S to save file
  - Ctrl+Q to quit (with warning if unsaved changes)
- **Status Bar**: Shows filename, modification status, line/column, and character count

## Usage

1. Make sure you have the NVDA remote server running
2. Set up your configuration (use `../../setup.sh` from the root if needed)
3. Run the example:
   ```bash
   go run .
   ```
4. Connect with a controller client to the same server
5. Use Tab to navigate to the textarea
6. Edit the text using keyboard
7. Use Ctrl+S to save
8. Use Ctrl+Q to quit

## File Edited

The example edits a file called `editme.txt` in the same directory. If it doesn't exist, it will be created.

## Controls

- **Arrow Keys**: Navigate character by character
- **Ctrl+Left/Right**: Navigate word by word
- **Home/End**: Go to start/end of current line
- **Backspace**: Delete character before cursor
- **Delete**: Delete character after cursor
- **Enter**: Insert new line (in TextArea)
- **Tab**: Move focus to next element
- **Ctrl+S**: Save file
- **Ctrl+Q**: Quit editor

## Screen Reader Behavior

The text editor provides rich screen reader feedback:

- When moving character by character, each character is announced
- Spaces are announced as "blank"
- When moving word by word (Ctrl+Left/Right), words are announced
- When moving line by line (Up/Down), line content is announced
- At text boundaries, appropriate messages are announced ("beginning of text", "end of text", etc.)
- When saving, "File saved" is announced

## Implementation Notes

This example demonstrates:

1. **TextArea Usage**: Multi-line text input with full navigation
2. **Hotkey System**: Ctrl+S and Ctrl+Q hotkeys
3. **File I/O**: Reading and writing files
4. **Status Updates**: Dynamic status bar showing file state
5. **Modification Tracking**: Detecting when file has changed
6. **User Confirmation**: Warning before quitting with unsaved changes
