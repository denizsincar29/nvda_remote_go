package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

// WindowType represents different windows/screens in the application
type WindowType string

const (
	WindowMain       WindowType = "main"
	WindowCalculator WindowType = "calculator"
	WindowForm       WindowType = "form"
	WindowAbout      WindowType = "about"
)

// Application manages multiple windows and state
type Application struct {
	remote        *nvda_remote_go.NVDARemoteClient
	handler       *vgui.Handler
	logger        *slog.Logger
	currentWindow WindowType
	gui           *vgui.GUI
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
	app.currentWindow = WindowMain
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
	app.currentWindow = WindowCalculator
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
	app.currentWindow = WindowForm
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
	app.currentWindow = WindowAbout
	app.gui = vgui.NewGUI()

	// Title
	app.gui.AddElement(vgui.NewLabel("About Unified VGUI Demo"))
	app.gui.AddElement(vgui.NewLabel("This is a demonstration of the NVDA Remote Go virtual GUI system."))
	app.gui.AddElement(vgui.NewLabel("It shows how to create multiple windows/screens in a single application."))
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

// updateHandler updates or creates the handler with the current GUI
func (app *Application) updateHandler() {
	if app.handler != nil {
		app.handler.Stop()
	}
	app.handler = vgui.NewHandler(app.remote, app.gui, app.logger)
	app.handler.Start()
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
