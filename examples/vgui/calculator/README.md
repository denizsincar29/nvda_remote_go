# Remote Calculator Example

An accessible calculator interface for remote use.

## Features

- **Basic Operations**: Addition, subtraction, multiplication, division
- **Number Buttons**: 0-9 buttons for input
- **Keyboard Input**: Type numbers and operators directly
- **Display**: Shows current value
- **History**: Tracks recent calculations
- **Clear Function**: Reset calculator state

## Usage

1. Ensure NVDA remote server is running
2. Configure your connection settings
3. Run the example:
   ```bash
   go run .
   ```
4. Connect with a controller client
5. Use number keys or navigate to number buttons with Tab
6. Use operator keys (+, -, *, /) or their buttons
7. Press = or Enter to calculate

## Controls

### Keyboard Shortcuts
- **0-9**: Enter numbers
- **+**: Addition
- **-**: Subtraction
- *****: Multiplication
- **/**: Division
- **=**: Calculate result (Enter also works on equals button)
- **c**: Clear calculator
- **Tab**: Navigate between elements
- **Up/Down**: Navigate history

### Buttons
- Number buttons (0-9)
- Operator buttons (+, -, *, /)
- Equals button (=)
- Clear button (C)
- History listbox (shows last 10 calculations)

## Screen Reader Announcements

- Numbers are announced as they're entered
- Operators are announced when selected
- Results are announced after calculation
- History entries are read when navigating the history list

## Examples

### Addition
1. Type `5` or click 5 button
2. Type `+` or click + button  
3. Type `3` or click 3 button
4. Type `=` or press Enter on equals button
5. Result: "8"

### Chain Calculations
1. Type `10`
2. Type `+`
3. Type `5`
4. Type `=` → Result: 15
5. Type `*`
6. Type `2`
7. Type `=` → Result: 30

## Implementation Notes

This example demonstrates:

1. **Button Grid**: Multiple buttons for calculator interface
2. **Hotkey System**: Direct keyboard input
3. **State Management**: Tracking operator and operands
4. **History Tracking**: Storing calculation history
5. **Display Updates**: Showing current value
6. **Default Button**: Enter key activates equals button
7. **Number Formatting**: Clean display of integers and decimals

## Limitations

- Decimal point handling is basic
- No scientific operations
- No memory functions (M+, MR, etc.)
- History is not persisted between sessions
