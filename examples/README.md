# NVDA Remote Go Examples

This directory contains various example applications demonstrating different features of the NVDA Remote Go library.

## Directory Structure

```
examples/
├── audio/
│   ├── melody/        - Plays a melody when spacebar is pressed
│   └── piano/         - Interactive piano using key presses
├── basic/
│   ├── main_example/  - Basic example showing speech messages
│   └── tell_progress/ - Listens for progress bar beep events
├── controller/
│   └── type_hello_cmd/ - Controller that types commands remotely
├── vgui/              - Virtual GUI unified menu with all examples
└── shared/
    └── config/        - Shared configuration loader for all examples
```

## Setup

Before running any example, you need to configure your NVDA Remote credentials:

### Option 1: Use the setup script (recommended)
Run the interactive setup script from the root directory:
```bash
./setup.sh
```

### Option 2: Manual configuration
Create a `.env` file in the root directory with:
```
NVDA_REMOTE_KEY=your_key_here
NVDA_REMOTE_HOST=nvdaremote.ru
NVDA_REMOTE_PORT=6837
```

## Running Examples

Navigate to any example directory and run:
```bash
# For most examples
cd examples/basic/main_example
go run .

# For VGUI unified menu (all GUI examples)
go run ./examples/vgui
```

## Example Descriptions

### Basic Examples
- **main_example**: Connects as a slave and sends "Hello, nvda user!" every 5 seconds
- **tell_progress**: Master client that listens for progress bar beep events and converts them to percentages

### Audio Examples
- **melody**: Slave client that plays a melody when spacebar is pressed
- **piano**: Slave client that maps keyboard keys to musical notes

### Controller Examples
- **type_hello_cmd**: Master client that opens cmd and types "Hello from NVDA remote client" when someone joins

### Virtual GUI Examples
- **vgui**: Unified menu launcher with all vgui examples:
  - Simple Calculator: Basic arithmetic operations
  - Simple Form: Form with listboxes, checkboxes, and buttons
  - Number Guessing Game: Interactive game with scoring
  - Text Editor: Simple text file editor
  - Todo List Manager: CRUD operations with persistent storage
  
Run all examples from one application:
```bash
go run ./examples/vgui
```

## Requirements

- Go 1.24.1 or later
- NVDA Remote key (get one from nvdaremote.ru or your NVDA Remote server)
- NVDA Remote addon installed on the computer you want to connect to
