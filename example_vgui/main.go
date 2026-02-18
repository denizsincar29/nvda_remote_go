package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	"github.com/denizsincar29/nvda_remote_go/exampleconfig"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

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

	// Create a virtual GUI
	gui := vgui.NewGUI()

	// Add a welcome label
	gui.AddElement(vgui.NewLabel("Welcome to the virtual GUI demo"))

	// Add a gender selection listbox
	genderList := vgui.NewListBox("Choose your gender", []string{"Male", "Female", "Other", "Prefer not to say"})
	gui.AddElement(genderList)

	// Add an age range listbox
	ageList := vgui.NewListBox("Choose your age range", []string{"Under 18", "18-25", "26-35", "36-45", "46-55", "Over 55"})
	gui.AddElement(ageList)

	// Add a checkbox for newsletter subscription
	newsletterCheckbox := vgui.NewCheckBox("Subscribe to newsletter", false)
	newsletterCheckbox.OnToggle = func(checked bool) string {
		if checked {
			return "Newsletter subscription enabled"
		}
		return "Newsletter subscription disabled"
	}
	gui.AddElement(newsletterCheckbox)

	// Add an OK button
	okButton := vgui.NewButton("OK")
	okButton.OnClick = func() string {
		gender := genderList.GetSelectedItem()
		age := ageList.GetSelectedItem()
		newsletter := "No"
		if newsletterCheckbox.Checked {
			newsletter = "Yes"
		}
		return fmt.Sprintf("Form submitted. Gender: %s, Age: %s, Newsletter: %s", gender, age, newsletter)
	}
	gui.AddElement(okButton)

	// Add a Cancel button
	cancelButton := vgui.NewButton("Cancel")
	cancelButton.OnClick = func() string {
		return "Form cancelled"
	}
	gui.AddElement(cancelButton)

	// Create and start the vgui handler
	handler := vgui.NewHandler(remote, gui, logger)
	handler.Start()

	logger.Info("Virtual GUI is ready. Connect with a controller client and use Tab to navigate, Enter/Space to activate.")
	logger.Info("Press Ctrl+C to exit")

	// Keep the program running and check for errors
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
