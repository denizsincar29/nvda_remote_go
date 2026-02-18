# Todo List Manager Example

An interactive todo list manager with add, toggle, and delete operations.

## Features

- **Todo Management**: Add, complete, and delete todos
- **Persistent Storage**: Todos saved to JSON file
- **Keyboard Shortcuts**: 
  - Ctrl+N: Add new todo
  - Space: Toggle todo completion
  - Delete button: Delete selected todo
- **ListBox Navigation**: Up/Down arrows to navigate todos
- **Completion Status**: Visual indicators for completed todos ([X]) vs incomplete ([ ])

## Usage

1. Ensure NVDA remote server is running
2. Configure your connection settings
3. Run the example:
   ```bash
   go run .
   ```
4. Connect with a controller client
5. Use Tab to navigate, Up/Down to select todos
6. Use buttons or hotkeys to manage todos

## Data Storage

Todos are stored in `todos.json` in the same directory. The file format is:

```json
{
  "todos": [
    {
      "text": "Example todo",
      "completed": false
    }
  ]
}
```

You can manually edit this file to add or modify todos with more detailed text.

## Controls

- **Tab**: Move between elements
- **Up/Down**: Navigate todo items
- **Space**: Toggle completion status
- **Ctrl+N**: Add new todo
- **Enter**: Activate selected button

## Buttons

- **Add New Todo**: Creates a new todo (Ctrl+N)
- **Toggle Complete**: Marks todo as complete/incomplete (Space)
- **Delete Todo**: Removes selected todo

## Screen Reader Announcements

- When navigating the list, each todo with its completion status is announced
- When toggling completion, "marked as completed" or "marked as incomplete" is announced
- When deleting, the deleted todo text is announced
- Position in list is announced (e.g., "1 of 5")

## Implementation Notes

This example demonstrates:

1. **ListBox Usage**: Display and navigate items
2. **JSON Persistence**: Load and save data
3. **Hotkey System**: Quick keyboard access
4. **Button Actions**: CRUD operations
5. **Dynamic Updates**: Refresh list after changes
6. **Status Tracking**: Completed vs incomplete states
