package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

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

	// Calculator state
	var currentValue float64
	var previousValue float64
	var operator string
	var newNumber bool = true
	history := []string{}

	// Create GUI
	gui := vgui.NewGUI()

	// Add title
	gui.AddElement(vgui.NewLabel("Remote Calculator"))

	// Display textbox
	display := vgui.NewTextBox("Display", "0")
	gui.AddElement(display)

	// Helper to update display
	updateDisplay := func(value float64) {
		display.Text = formatNumber(value)
		display.CursorPos = len(display.Text)
	}

	// Helper to perform calculation
	calculate := func() float64 {
		result := previousValue
		switch operator {
		case "+":
			result = previousValue + currentValue
		case "-":
			result = previousValue - currentValue
		case "*":
			result = previousValue * currentValue
		case "/":
			if currentValue != 0 {
				result = previousValue / currentValue
			} else {
				return previousValue // Division by zero
			}
		default:
			result = currentValue
		}
		return result
	}

	// Number buttons (0-9)
	for i := 0; i <= 9; i++ {
		num := i // Capture for closure
		btn := vgui.NewButton(fmt.Sprintf("%d", num))
		btn.OnClick = func() string {
			if newNumber {
				currentValue = float64(num)
				newNumber = false
			} else {
				currentValue = currentValue*10 + float64(num)
			}
			updateDisplay(currentValue)
			return fmt.Sprintf("%d", num)
		}
		gui.AddElement(btn)
	}

	// Operator buttons
	operators := []string{"+", "-", "*", "/"}
	for _, op := range operators {
		operation := op // Capture for closure
		btn := vgui.NewButton(operation)
		btn.OnClick = func() string {
			if operator != "" {
				currentValue = calculate()
			} else {
				currentValue = currentValue
			}
			previousValue = currentValue
			operator = operation
			newNumber = true
			updateDisplay(currentValue)
			return operation
		}
		gui.AddElement(btn)
	}

	// Equals button
	equalsBtn := vgui.NewButton("=")
	equalsBtn.IsDefault = true
	equalsBtn.OnClick = func() string {
		if operator != "" {
			result := calculate()
			historyEntry := fmt.Sprintf("%s %s %s = %s",
				formatNumber(previousValue), operator, formatNumber(currentValue), formatNumber(result))
			history = append(history, historyEntry)
			logger.Info("Calculation", "result", result, "history", historyEntry)
			
			currentValue = result
			previousValue = 0
			operator = ""
			newNumber = true
			updateDisplay(result)
			
			return fmt.Sprintf("Equals %s", formatNumber(result))
		}
		return "Equals"
	}
	gui.AddElement(equalsBtn)

	// Clear button
	clearBtn := vgui.NewButton("Clear")
	clearBtn.OnClick = func() string {
		currentValue = 0
		previousValue = 0
		operator = ""
		newNumber = true
		updateDisplay(0)
		return "Cleared"
	}
	gui.AddElement(clearBtn)

	// Decimal point button
	decimalBtn := vgui.NewButton(".")
	decimalBtn.OnClick = func() string {
		// For simplicity, decimal handling is basic
		return "Decimal point"
	}
	gui.AddElement(decimalBtn)

	// History listbox
	historyList := vgui.NewListBox("History", []string{"No history yet"})
	gui.AddElement(historyList)

	// Update history display periodically
	updateHistory := func() {
		if len(history) > 0 {
			// Show last 10 entries
			start := 0
			if len(history) > 10 {
				start = len(history) - 10
			}
			historyList.Items = history[start:]
			historyList.SelectedIndex = len(historyList.Items) - 1
		}
	}

	// Register hotkeys for numbers
	for i := 0; i <= 9; i++ {
		num := i
		gui.RegisterHotkey(fmt.Sprintf("%d", num), func() string {
			if newNumber {
				currentValue = float64(num)
				newNumber = false
			} else {
				currentValue = currentValue*10 + float64(num)
			}
			updateDisplay(currentValue)
			return fmt.Sprintf("%d", num)
		})
	}

	// Register hotkeys for operators
	gui.RegisterHotkey("+", func() string {
		if operator != "" {
			currentValue = calculate()
		}
		previousValue = currentValue
		operator = "+"
		newNumber = true
		updateDisplay(currentValue)
		return "Plus"
	})

	gui.RegisterHotkey("-", func() string {
		if operator != "" {
			currentValue = calculate()
		}
		previousValue = currentValue
		operator = "-"
		newNumber = true
		updateDisplay(currentValue)
		return "Minus"
	})

	gui.RegisterHotkey("*", func() string {
		if operator != "" {
			currentValue = calculate()
		}
		previousValue = currentValue
		operator = "*"
		newNumber = true
		updateDisplay(currentValue)
		return "Multiply"
	})

	gui.RegisterHotkey("/", func() string {
		if operator != "" {
			currentValue = calculate()
		}
		previousValue = currentValue
		operator = "/"
		newNumber = true
		updateDisplay(currentValue)
		return "Divide"
	})

	gui.RegisterHotkey("=", func() string {
		return equalsBtn.OnActivate()
	})

	gui.RegisterHotkey("c", func() string {
		return clearBtn.OnActivate()
	})

	// Create and start handler
	handler := vgui.NewHandler(remote, gui, logger)
	handler.Start()

	logger.Info("Calculator is ready")
	logger.Info("Controls:")
	logger.Info("  - Tab: Navigate between buttons")
	logger.Info("  - 0-9: Number input")
	logger.Info("  - +, -, *, /: Operations")
	logger.Info("  - =: Calculate result")
	logger.Info("  - c: Clear")
	logger.Info("Press Ctrl+C to exit")

	// Keep running and update history
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-remote.Errors():
			logger.Error("Error from NVDA remote client", "error", err)
			e.Must(err, "Fatal error from NVDA remote client")
		case <-ticker.C:
			if handler.IsActive() {
				updateHistory()
			}
		}
	}
}

// formatNumber formats a float for display
func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	s := fmt.Sprintf("%.2f", f)
	// Remove trailing zeros after decimal point
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}
