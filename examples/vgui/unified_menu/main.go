package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

// WindowType represents different windows/screens in the application
type WindowType string

const (
	WindowDesktop    WindowType = "desktop"
	WindowMain       WindowType = "main"
	WindowCalculator WindowType = "calculator"
	WindowForm       WindowType = "form"
	WindowGame       WindowType = "game"
	WindowTextEditor WindowType = "text_editor"
	WindowTodo       WindowType = "todo"
	WindowAbout      WindowType = "about"
)

// Application manages multiple windows and state
type Application struct {
	remote        *nvda_remote_go.NVDARemoteClient
	handler       *vgui.Handler
	logger        *slog.Logger
	currentWindow WindowType
	windowStack   []WindowType  // Stack of open windows
	gui           *vgui.GUI
	
	// Game state
	gameRNG          *rand.Rand
	gameTarget       int
	gameAttempts     int
	gameMaxAttempts  int
	gameOver         bool
	gameScore        int
	
	// Text editor state
	editorFile       string
	editorContent    string
	editorModified   bool
	
	// Todo state
	todos            []Todo
}

// Todo represents a todo item
type Todo struct {
	Text      string `json:"text"`
	Completed bool   `json:"completed"`
}

// TodoList represents a collection of todos
type TodoList struct {
	Todos []Todo `json:"todos"`
}

func main() {
	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	e := goerror.NewError(logger)

	// Load configuration
	config := exampleconfig.Load()

	// Connect to NVDA remote server
	logger.Info("Connecting to NVDA remote server", "host", config.Host, "port", config.Port)
	remote, err := nvda_remote_go.NewClient(config.Host, config.Port, config.Key, "slave", logger)
	e.Must(err, "Failed to create NVDA remote client")
	defer remote.Close()

	logger.Info("Connected to NVDA remote server")

	// Create application
	app := &Application{
		remote:        remote,
		logger:        logger,
		currentWindow: WindowMain,
		windowStack:   []WindowType{WindowMain}, // Initialize with main window
	}

	// Initialize with main menu
	app.showMainMenu()

	logger.Info("Unified Menu Demo is ready")
	logger.Info("Navigate with Tab, use Enter to activate buttons")
	logger.Info("Press Ctrl+C to exit")

	// Keep running
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-remote.Errors():
			logger.Error("Error from NVDA remote client", "error", err)
			e.Must(err, "Fatal error from NVDA remote client")
		case <-ticker.C:
			// Keep alive
		}
	}
}

// showMainMenu displays the main menu
func (app *Application) showMainMenu() {
	// Reset to main window (clear stack except main)
	app.currentWindow = WindowMain
	app.windowStack = []WindowType{WindowMain}
	app.gui = vgui.NewGUI()

	// Title
	app.gui.AddElement(vgui.NewLabel("Unified VGUI Demo - Main Menu"))
	app.gui.AddElement(vgui.NewLabel("Select an example to run:"))

	// Calculator button
	calcButton := vgui.NewButton("Simple Calculator")
	calcButton.OnClick = func() string {
		app.showCalculator()
		return "Opening Calculator"
	}
	app.gui.AddElement(calcButton)

	// Form button
	formButton := vgui.NewButton("Simple Form")
	formButton.OnClick = func() string {
		app.showForm()
		return "Opening Form"
	}
	app.gui.AddElement(formButton)

	// Game button
	gameButton := vgui.NewButton("Number Guessing Game")
	gameButton.OnClick = func() string {
		app.showGame()
		return "Opening Game"
	}
	app.gui.AddElement(gameButton)

	// Text Editor button
	editorButton := vgui.NewButton("Text Editor")
	editorButton.OnClick = func() string {
		app.showTextEditor()
		return "Opening Text Editor"
	}
	app.gui.AddElement(editorButton)

	// Todo button
	todoButton := vgui.NewButton("Todo List")
	todoButton.OnClick = func() string {
		app.showTodo()
		return "Opening Todo List"
	}
	app.gui.AddElement(todoButton)

	// About button
	aboutButton := vgui.NewButton("About")
	aboutButton.OnClick = func() string {
		app.showAbout()
		return "Opening About"
	}
	app.gui.AddElement(aboutButton)

	// Exit button
	exitButton := vgui.NewButton("Exit")
	exitButton.OnClick = func() string {
		app.logger.Info("Exiting application")
		os.Exit(0)
		return "Exiting"
	}
	app.gui.AddElement(exitButton)

	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.logger.Info("Exiting application")
		os.Exit(0)
		return "Exiting"
	})

	// Update handler with new GUI
	app.updateHandler()
}

// showCalculator displays a simple calculator
func (app *Application) showCalculator() {
	app.pushWindow(WindowCalculator)
	app.gui = vgui.NewGUI()

	// Title
	app.gui.AddElement(vgui.NewLabel("Simple Calculator"))

	// Display
	display := vgui.NewTextBox("Display", "0")
	app.gui.AddElement(display)

	// Result label
	resultLabel := vgui.NewLabel("Enter two numbers separated by an operator (+, -, *, /)")
	app.gui.AddElement(resultLabel)

	// Calculate button
	calcButton := vgui.NewButton("Calculate")
	calcButton.IsDefault = true
	calcButton.OnClick = func() string {
		result := calculateExpression(display.Text)
		resultLabel.Name = fmt.Sprintf("Result: %s", result)
		return result
	}
	app.gui.AddElement(calcButton)

	// Clear button
	clearButton := vgui.NewButton("Clear")
	clearButton.OnClick = func() string {
		display.Text = "0"
		display.CursorPos = 1
		resultLabel.Name = "Enter two numbers separated by an operator (+, -, *, /)"
		return "Cleared"
	}
	app.gui.AddElement(clearButton)

	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.OnClick = func() string {
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)

	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})

	app.updateHandler()
}

// showForm displays a simple form
func (app *Application) showForm() {
	app.pushWindow(WindowForm)
	app.gui = vgui.NewGUI()

	// Title
	app.gui.AddElement(vgui.NewLabel("Simple Form Demo"))

	// Name textbox
	nameBox := vgui.NewTextBox("Your Name", "")
	app.gui.AddElement(nameBox)

	// Gender listbox
	genderList := vgui.NewListBox("Gender", []string{"Male", "Female", "Other", "Prefer not to say"})
	app.gui.AddElement(genderList)

	// Newsletter checkbox
	newsletterCheckbox := vgui.NewCheckBox("Subscribe to newsletter", false)
	app.gui.AddElement(newsletterCheckbox)

	// Submit button
	submitButton := vgui.NewButton("Submit")
	submitButton.IsDefault = true
	submitButton.OnClick = func() string {
		name := nameBox.Text
		gender := genderList.GetSelectedItem()
		newsletter := "No"
		if newsletterCheckbox.Checked {
			newsletter = "Yes"
		}
		return fmt.Sprintf("Form submitted. Name: %s, Gender: %s, Newsletter: %s", name, gender, newsletter)
	}
	app.gui.AddElement(submitButton)

	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.OnClick = func() string {
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)

	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})

	app.updateHandler()
}

// showAbout displays the about screen
func (app *Application) showAbout() {
	app.pushWindow(WindowAbout)
	app.gui = vgui.NewGUI()

	// Title
	app.gui.AddElement(vgui.NewLabel("About Unified VGUI Demo"))
	app.gui.AddElement(vgui.NewLabel("This is a demonstration of the NVDA Remote Go virtual GUI system."))
	app.gui.AddElement(vgui.NewLabel("All VGUI examples are unified in this single menu-driven application."))
	app.gui.AddElement(vgui.NewLabel(""))
	app.gui.AddElement(vgui.NewLabel("Available Examples:"))
	app.gui.AddElement(vgui.NewLabel("- Simple Calculator: Perform arithmetic operations"))
	app.gui.AddElement(vgui.NewLabel("- Simple Form: Fill out forms with various controls"))
	app.gui.AddElement(vgui.NewLabel("- Number Guessing Game: Interactive game with audio feedback"))
	app.gui.AddElement(vgui.NewLabel("- Text Editor: Edit text files with full accessibility"))
	app.gui.AddElement(vgui.NewLabel("- Todo List: Manage todos with persistent storage"))
	app.gui.AddElement(vgui.NewLabel(""))
	app.gui.AddElement(vgui.NewLabel("Features demonstrated:"))
	app.gui.AddElement(vgui.NewLabel("- Multiple windows with navigation"))
	app.gui.AddElement(vgui.NewLabel("- Text input with keyboard layout support"))
	app.gui.AddElement(vgui.NewLabel("- List boxes and checkboxes"))
	app.gui.AddElement(vgui.NewLabel("- Hotkeys (Escape to go back)"))
	app.gui.AddElement(vgui.NewLabel("- Alt+Shift to switch keyboard layouts"))

	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.IsDefault = true
	backButton.OnClick = func() string {
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)

	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})

	app.updateHandler()
}

// showGame displays the number guessing game
func (app *Application) showGame() {
	app.pushWindow(WindowGame)
	app.gui = vgui.NewGUI()
	
	// Initialize game state
	if app.gameRNG == nil {
		app.gameRNG = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	app.gameTarget = app.gameRNG.Intn(100) + 1
	app.gameAttempts = 0
	app.gameMaxAttempts = 7
	app.gameOver = false
	
	// Title
	app.gui.AddElement(vgui.NewLabel("Number Guessing Game - Guess a number between 1 and 100"))
	app.gui.AddElement(vgui.NewLabel(fmt.Sprintf("You have %d attempts to guess the number", app.gameMaxAttempts)))
	
	// Input textbox
	inputBox := vgui.NewTextBox("Your Guess", "")
	app.gui.AddElement(inputBox)
	
	// Result label
	resultLabel := vgui.NewLabel("Enter your guess and press Submit")
	app.gui.AddElement(resultLabel)
	
	// Attempts label
	attemptsLabel := vgui.NewLabel(fmt.Sprintf("Attempts: %d / %d", app.gameAttempts, app.gameMaxAttempts))
	app.gui.AddElement(attemptsLabel)
	
	// Score label
	scoreLabel := vgui.NewLabel(fmt.Sprintf("Score: %d", app.gameScore))
	app.gui.AddElement(scoreLabel)
	
	// Submit button
	submitBtn := vgui.NewButton("Submit Guess")
	submitBtn.IsDefault = true
	submitBtn.OnClick = func() string {
		if app.gameOver {
			return "Game is over. Click New Game to play again"
		}
		
		// Parse guess
		guess, err := strconv.Atoi(inputBox.Text)
		if err != nil || guess < 1 || guess > 100 {
			resultLabel.Name = "Invalid guess. Please enter a number between 1 and 100"
			return "Invalid guess"
		}
		
		// Clear input
		inputBox.Text = ""
		inputBox.CursorPos = 0
		
		app.gameAttempts++
		attemptsLabel.Name = fmt.Sprintf("Attempts: %d / %d", app.gameAttempts, app.gameMaxAttempts)
		
		// Check guess
		if guess == app.gameTarget {
			app.gameOver = true
			points := (app.gameMaxAttempts - app.gameAttempts + 1) * 10
			app.gameScore += points
			scoreLabel.Name = fmt.Sprintf("Score: %d", app.gameScore)
			resultLabel.Name = fmt.Sprintf("Congratulations! You guessed it in %d attempts! You earned %d points!", app.gameAttempts, points)
			return fmt.Sprintf("You won! The number was %d", app.gameTarget)
		} else if guess < app.gameTarget {
			resultLabel.Name = "Too low! Try a higher number"
			return "Too low"
		} else {
			resultLabel.Name = "Too high! Try a lower number"
			return "Too high"
		}
	}
	app.gui.AddElement(submitBtn)
	
	// New Game button
	newGameBtn := vgui.NewButton("New Game")
	newGameBtn.OnClick = func() string {
		app.showGame()
		return "Starting new game"
	}
	app.gui.AddElement(newGameBtn)
	
	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.OnClick = func() string {
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)
	
	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})
	
	app.updateHandler()
}

// showTextEditor displays a simple text editor
func (app *Application) showTextEditor() {
	app.pushWindow(WindowTextEditor)
	app.gui = vgui.NewGUI()
	
	// Initialize editor state
	if app.editorFile == "" {
		app.editorFile = "editme.txt"
		content, err := os.ReadFile(app.editorFile)
		if err != nil {
			app.editorContent = ""
		} else {
			app.editorContent = string(content)
		}
		app.editorModified = false
	}
	
	// Title
	app.gui.AddElement(vgui.NewLabel("Remote Text Editor - Use Ctrl+S to save"))
	
	// Textarea for editing
	textarea := vgui.NewTextArea("Edit Content", app.editorContent)
	textarea.OnChange = func(text string) string {
		app.editorContent = text
		app.editorModified = true
		return ""
	}
	app.gui.AddElement(textarea)
	
	// Status label
	statusLabel := vgui.NewLabel(fmt.Sprintf("File: %s | Modified: %v", app.editorFile, app.editorModified))
	app.gui.AddElement(statusLabel)
	
	// Save button
	saveBtn := vgui.NewButton("Save")
	saveBtn.OnClick = func() string {
		err := os.WriteFile(app.editorFile, []byte(app.editorContent), 0644)
		if err != nil {
			return "Error saving file: " + err.Error()
		}
		app.editorModified = false
		statusLabel.Name = fmt.Sprintf("File: %s | Modified: %v", app.editorFile, app.editorModified)
		return "File saved"
	}
	app.gui.AddElement(saveBtn)
	
	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.OnClick = func() string {
		if app.editorModified {
			return "File has unsaved changes. Save first or press Escape to go back anyway"
		}
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)
	
	// Register hotkeys
	app.gui.RegisterHotkey("ctrl+s", func() string {
		return saveBtn.OnActivate()
	})
	
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})
	
	app.updateHandler()
}

// showTodo displays a simple todo list
func (app *Application) showTodo() {
	app.pushWindow(WindowTodo)
	app.gui = vgui.NewGUI()
	
	// Load todos if not loaded
	if app.todos == nil {
		app.loadTodos()
	}
	
	// Title
	app.gui.AddElement(vgui.NewLabel("Todo List Manager"))
	
	// Create listbox with todos
	todoItems := app.getTodoStrings()
	listbox := vgui.NewListBox("Todos", todoItems)
	app.gui.AddElement(listbox)
	
	// Helper to refresh list
	refreshList := func() {
		todoItems = app.getTodoStrings()
		listbox.Items = todoItems
		if listbox.SelectedIndex >= len(todoItems) {
			listbox.SelectedIndex = len(todoItems) - 1
		}
		if listbox.SelectedIndex < 0 && len(todoItems) > 0 {
			listbox.SelectedIndex = 0
		}
	}
	
	// Add button
	addBtn := vgui.NewButton("Add New Todo")
	addBtn.OnClick = func() string {
		newTodo := Todo{
			Text:      "New Todo (edit in todos.json)",
			Completed: false,
		}
		app.todos = append(app.todos, newTodo)
		refreshList()
		app.saveTodos()
		return fmt.Sprintf("Added new todo. Total: %d", len(app.todos))
	}
	app.gui.AddElement(addBtn)
	
	// Toggle button
	toggleBtn := vgui.NewButton("Toggle Complete")
	toggleBtn.OnClick = func() string {
		if len(app.todos) == 0 {
			return "No todos to toggle"
		}
		idx := listbox.SelectedIndex
		if idx >= 0 && idx < len(app.todos) {
			app.todos[idx].Completed = !app.todos[idx].Completed
			refreshList()
			app.saveTodos()
			status := "incomplete"
			if app.todos[idx].Completed {
				status = "completed"
			}
			return fmt.Sprintf("Todo marked as %s", status)
		}
		return "No todo selected"
	}
	app.gui.AddElement(toggleBtn)
	
	// Delete button
	deleteBtn := vgui.NewButton("Delete Todo")
	deleteBtn.OnClick = func() string {
		if len(app.todos) == 0 {
			return "No todos to delete"
		}
		idx := listbox.SelectedIndex
		if idx >= 0 && idx < len(app.todos) {
			app.todos = append(app.todos[:idx], app.todos[idx+1:]...)
			refreshList()
			app.saveTodos()
			return "Todo deleted"
		}
		return "No todo selected"
	}
	app.gui.AddElement(deleteBtn)
	
	// Back button
	backButton := vgui.NewButton("Back to Main Menu")
	backButton.OnClick = func() string {
		app.showMainMenu()
		return "Returning to main menu"
	}
	app.gui.AddElement(backButton)
	
	// Register hotkeys
	app.gui.RegisterHotkey("escape", func() string {
		app.showMainMenu()
		return "Returning to main menu"
	})
	
	app.updateHandler()
}

// loadTodos loads todos from file
func (app *Application) loadTodos() {
	const todosFile = "todos.json"
	data, err := os.ReadFile(todosFile)
	if err != nil {
		app.todos = []Todo{}
		return
	}
	
	var todoList TodoList
	if err := json.Unmarshal(data, &todoList); err != nil {
		app.todos = []Todo{}
		return
	}
	
	app.todos = todoList.Todos
}

// saveTodos saves todos to file
func (app *Application) saveTodos() {
	const todosFile = "todos.json"
	todoList := TodoList{Todos: app.todos}
	data, err := json.Marshal(todoList)
	if err != nil {
		app.logger.Error("Failed to marshal todos", "error", err)
		return
	}
	
	if err := os.WriteFile(todosFile, data, 0644); err != nil {
		app.logger.Error("Failed to write todos", "error", err)
	}
}

// getTodoStrings returns a string representation of todos
func (app *Application) getTodoStrings() []string {
	if len(app.todos) == 0 {
		return []string{"No todos yet"}
	}
	
	items := make([]string, len(app.todos))
	for i, todo := range app.todos {
		status := "[ ]"
		if todo.Completed {
			status = "[X]"
		}
		items[i] = fmt.Sprintf("%s %s", status, todo.Text)
	}
	return items
}

// updateHandler updates or creates the handler with the current GUI
func (app *Application) updateHandler() {
	if app.handler != nil {
		app.handler.Stop()
	}
	app.handler = vgui.NewHandler(app.remote, app.gui, app.logger)
	
	// Set up Alt+F4 close callback for all windows except desktop and main
	if app.currentWindow != WindowDesktop && app.currentWindow != WindowMain {
		app.gui.SetCloseCallback(func() string {
			return app.closeCurrentWindow()
		})
	}
	
	// Set up Win+D desktop hotkey
	app.gui.RegisterHotkey("win+d", func() string {
		app.showDesktop()
		return "Going to desktop"
	})
	
	app.handler.Start()
}

// pushWindow adds a window to the stack
func (app *Application) pushWindow(window WindowType) {
	app.windowStack = append(app.windowStack, window)
	app.currentWindow = window
	app.logger.Debug("Window opened", "window", window, "stack_size", len(app.windowStack))
}

// popWindow removes the current window and returns to previous
func (app *Application) popWindow() WindowType {
	if len(app.windowStack) <= 1 {
		// Don't pop the last window (main or desktop)
		return app.currentWindow
	}
	
	// Remove current window from stack
	app.windowStack = app.windowStack[:len(app.windowStack)-1]
	
	// Return to previous window
	previous := app.windowStack[len(app.windowStack)-1]
	app.currentWindow = previous
	app.logger.Debug("Window closed", "previous", previous, "stack_size", len(app.windowStack))
	
	return previous
}

// closeCurrentWindow closes the current window and returns to previous
func (app *Application) closeCurrentWindow() string {
	previous := app.popWindow()
	
	// Show the previous window
	switch previous {
	case WindowDesktop:
		app.showDesktop()
	case WindowMain:
		app.showMainMenu()
	case WindowCalculator:
		app.showCalculator()
	case WindowForm:
		app.showForm()
	case WindowGame:
		app.showGame()
	case WindowTextEditor:
		app.showTextEditor()
	case WindowTodo:
		app.showTodo()
	case WindowAbout:
		app.showAbout()
	}
	
	return fmt.Sprintf("Closed window, returning to %s", previous)
}

// showDesktop displays the desktop window (accessible via Win+D)
func (app *Application) showDesktop() {
	app.currentWindow = WindowDesktop
	app.gui = vgui.NewGUI()
	
	// Title
	app.gui.AddElement(vgui.NewLabel("Desktop - Windows are minimized"))
	
	// List all open applications (windows in stack)
	if len(app.windowStack) > 1 {
		app.gui.AddElement(vgui.NewLabel(fmt.Sprintf("Open windows: %d", len(app.windowStack)-1)))
		
		// Show window list
		for i, win := range app.windowStack {
			if win != WindowDesktop {
				app.gui.AddElement(vgui.NewLabel(fmt.Sprintf("%d. %s", i+1, win)))
			}
		}
	} else {
		app.gui.AddElement(vgui.NewLabel("No open windows"))
	}
	
	// Button to return to main menu
	mainMenuBtn := vgui.NewButton("Main Menu")
	mainMenuBtn.IsDefault = true
	mainMenuBtn.OnClick = func() string {
		app.showMainMenu()
		return "Opening Main Menu"
	}
	app.gui.AddElement(mainMenuBtn)
	
	app.updateHandler()
}

// calculateExpression performs simple calculation on an expression string
func calculateExpression(expr string) string {
	var num1, num2 float64
	var op rune
	
	// Very simple parser - just for demo purposes
	// Format: "num1 op num2" e.g., "5 + 3"
	n, err := fmt.Sscanf(expr, "%f %c %f", &num1, &op, &num2)
	if err != nil || n != 3 {
		return "Invalid expression. Use format: number operator number (e.g., 5 + 3)"
	}

	var result float64
	switch op {
	case '+':
		result = num1 + num2
	case '-':
		result = num1 - num2
	case '*':
		result = num1 * num2
	case '/':
		if num2 == 0 {
			return "Error: Division by zero"
		}
		result = num1 / num2
	default:
		return fmt.Sprintf("Unknown operator: %c", op)
	}

	return fmt.Sprintf("%.2f %c %.2f = %.2f", num1, op, num2, result)
}
