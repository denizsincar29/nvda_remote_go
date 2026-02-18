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

const defaultFile = "editme.txt"

func main() {
	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	e := goerror.NewError(logger)

	// Load configuration from .env file
	config := exampleconfig.Load()

	// Create NVDA remote client in slave mode (required for vgui)
	logger.Info("Connecting to NVDA remote server", "host", config.Host, "port", config.Port)
	remote, err := nvda_remote_go.NewClient(config.Host, config.Port, config.Key, "slave", logger)
	e.Must(err, "Failed to create NVDA remote client")
	defer remote.Close()

	logger.Info("Connected to NVDA remote server")

	// Load file content or create empty file
	content, err := os.ReadFile(defaultFile)
	if err != nil {
		// File doesn't exist, create it
		content = []byte("")
		logger.Info("Creating new file", "filename", defaultFile)
	} else {
		logger.Info("Loaded existing file", "filename", defaultFile, "size", len(content))
	}

	// Track if file has been modified
	modified := false
	savedContent := string(content)

	// Create a virtual GUI
	gui := vgui.NewGUI()

	// Add instructions label
	gui.AddElement(vgui.NewLabel("Remote Text Editor - Use Ctrl+S to save, Ctrl+Q to quit"))

	// Add textarea for editing
	textarea := vgui.NewTextArea("Edit Content", string(content))
	textarea.OnChange = func(text string) string {
		modified = (text != savedContent)
		// Return empty to not announce on every change
		return ""
	}
	gui.AddElement(textarea)

	// Add status label
	statusLabel := vgui.NewLabel(getStatus(defaultFile, len(content), 1, 1, modified))
	gui.AddElement(statusLabel)

	// Register hotkeys
	// Ctrl+S: Save file
	gui.RegisterHotkey("ctrl+s", func() string {
		err := os.WriteFile(defaultFile, []byte(textarea.Text), 0644)
		if err != nil {
			logger.Error("Failed to save file", "error", err)
			return "Error saving file: " + err.Error()
		}
		savedContent = textarea.Text
		modified = false
		statusLabel.Name = getStatus(defaultFile, len(textarea.Text), textarea.Row+1, textarea.Col+1, modified)
		logger.Info("File saved", "filename", defaultFile)
		return "File saved"
	})

	// Ctrl+Q: Quit with confirmation if modified
	gui.RegisterHotkey("ctrl+q", func() string {
		if modified {
			// Show confirmation dialog
			return "File has unsaved changes. Save first with Ctrl+S or close anyway?"
		}
		logger.Info("Exiting text editor")
		os.Exit(0)
		return "Exiting"
	})

	// Create and start the vgui handler
	handler := vgui.NewHandler(remote, gui, logger)
	handler.Start()

	logger.Info("Text Editor is ready")
	logger.Info("Controls:")
	logger.Info("  - Arrow keys: Navigate text")
	logger.Info("  - Ctrl+Left/Right: Navigate by words")
	logger.Info("  - Home/End: Start/End of line")
	logger.Info("  - Ctrl+S: Save file")
	logger.Info("  - Ctrl+Q: Quit")
	logger.Info("Press Ctrl+C to force exit")

	// Keep the program running and check for errors
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-remote.Errors():
			logger.Error("Error from NVDA remote client", "error", err)
			e.Must(err, "Fatal error from NVDA remote client")
		case <-ticker.C:
			// Update status periodically
			if handler.IsActive() {
				statusLabel.Name = getStatus(defaultFile, len(textarea.Text), textarea.Row+1, textarea.Col+1, modified)
			}
		}
	}
}

// getStatus returns a status string for the status bar
func getStatus(filename string, charCount, row, col int, modified bool) string {
	modStr := ""
	if modified {
		modStr = " [Modified]"
	}
	return fmt.Sprintf("Status: %s%s | Line %d, Column %d | %d characters", filename, modStr, row, col, charCount)
}
