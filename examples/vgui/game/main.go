package main

import (
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

	// Game state
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	targetNumber := rng.Intn(100) + 1
	attempts := 0
	maxAttempts := 7
	gameOver := false
	score := 0

	// Create GUI
	gui := vgui.NewGUI()

	// Add title
	gui.AddElement(vgui.NewLabel("Number Guessing Game - Guess a number between 1 and 100"))

	// Instructions
	gui.AddElement(vgui.NewLabel(fmt.Sprintf("You have %d attempts to guess the number", maxAttempts)))

	// Input textbox
	inputBox := vgui.NewTextBox("Your Guess", "")
	gui.AddElement(inputBox)

	// Result label
	resultLabel := vgui.NewLabel("Enter your guess and press Submit")
	gui.AddElement(resultLabel)

	// Attempts label
	attemptsLabel := vgui.NewLabel(fmt.Sprintf("Attempts: %d / %d", attempts, maxAttempts))
	gui.AddElement(attemptsLabel)

	// Score label
	scoreLabel := vgui.NewLabel(fmt.Sprintf("Score: %d", score))
	gui.AddElement(scoreLabel)

	// Submit button
	submitBtn := vgui.NewButton("Submit Guess")
	submitBtn.IsDefault = true
	submitBtn.OnClick = func() string {
		if gameOver {
			return "Game is over. Click New Game to play again"
		}

		// Parse guess
		guess, err := strconv.Atoi(inputBox.Text)
		if err != nil || guess < 1 || guess > 100 {
			resultLabel.Name = "Invalid guess. Please enter a number between 1 and 100"
			return "Invalid guess"
		}

		attempts++
		attemptsLabel.Name = fmt.Sprintf("Attempts: %d / %d", attempts, maxAttempts)

		// Check guess
		if guess == targetNumber {
			gameOver = true
			points := (maxAttempts - attempts + 1) * 10
			score += points
			scoreLabel.Name = fmt.Sprintf("Score: %d", score)
			resultLabel.Name = fmt.Sprintf("Congratulations! You guessed it in %d attempts! You earned %d points!", attempts, points)
			logger.Info("Game won", "attempts", attempts, "target", targetNumber)
			return fmt.Sprintf("You won! The number was %d", targetNumber)
		} else if guess < targetNumber {
			diff := targetNumber - guess
			hint := "higher"
			if diff <= 5 {
				hint = "a little higher"
			} else if diff <= 15 {
				hint = "higher"
			} else {
				hint = "much higher"
			}
			resultLabel.Name = fmt.Sprintf("Too low! Try %s. Attempts: %d / %d", hint, attempts, maxAttempts)
			
			// Play low tone
			remote.SendBeep(400, 100)
			
			return fmt.Sprintf("Too low, go %s", hint)
		} else {
			diff := guess - targetNumber
			hint := "lower"
			if diff <= 5 {
				hint = "a little lower"
			} else if diff <= 15 {
				hint = "lower"
			} else {
				hint = "much lower"
			}
			resultLabel.Name = fmt.Sprintf("Too high! Try %s. Attempts: %d / %d", hint, attempts, maxAttempts)
			
			// Play high tone
			remote.SendBeep(800, 100)
			
			return fmt.Sprintf("Too high, go %s", hint)
		}

		// Check if out of attempts
		if attempts >= maxAttempts && !gameOver {
			gameOver = true
			resultLabel.Name = fmt.Sprintf("Game Over! The number was %d. Click New Game to try again", targetNumber)
			logger.Info("Game lost", "attempts", attempts, "target", targetNumber)
			
			// Play game over tone
			remote.SendBeep(200, 300)
			
			return fmt.Sprintf("Game over! The number was %d", targetNumber)
		}

		// Clear input for next guess
		inputBox.Text = ""
		inputBox.CursorPos = 0

		return "Guess submitted"
	}
	gui.AddElement(submitBtn)

	// New Game button
	newGameBtn := vgui.NewButton("New Game")
	newGameBtn.OnClick = func() string {
		targetNumber = rng.Intn(100) + 1
		attempts = 0
		gameOver = false
		inputBox.Text = ""
		inputBox.CursorPos = 0
		resultLabel.Name = "Enter your guess and press Submit"
		attemptsLabel.Name = fmt.Sprintf("Attempts: %d / %d", attempts, maxAttempts)
		logger.Info("New game started", "target", targetNumber)
		
		// Play new game tone
		remote.SendBeep(600, 100)
		
		return "New game started! Guess a number between 1 and 100"
	}
	gui.AddElement(newGameBtn)

	// Hint button
	hintBtn := vgui.NewButton("Get Hint")
	hintBtn.OnClick = func() string {
		if gameOver {
			return "Game is over"
		}
		if attempts == 0 {
			return "Make a guess first"
		}
		
		// Give a hint based on target number
		var hint string
		if targetNumber <= 25 {
			hint = "The number is in the lower quarter (1-25)"
		} else if targetNumber <= 50 {
			hint = "The number is in the lower half (26-50)"
		} else if targetNumber <= 75 {
			hint = "The number is in the upper half (51-75)"
		} else {
			hint = "The number is in the upper quarter (76-100)"
		}
		
		// Deduct points for hint
		if score >= 5 {
			score -= 5
			scoreLabel.Name = fmt.Sprintf("Score: %d", score)
			return hint + " (5 points deducted)"
		}
		
		return hint + " (no points to deduct)"
	}
	gui.AddElement(hintBtn)

	// Register hotkeys
	gui.RegisterHotkey("ctrl+n", func() string {
		return newGameBtn.OnActivate()
	})

	gui.RegisterHotkey("ctrl+h", func() string {
		return hintBtn.OnActivate()
	})

	// Create and start handler
	handler := vgui.NewHandler(remote, gui, logger)
	handler.Start()

	logger.Info("Number Guessing Game is ready")
	logger.Info("Controls:")
	logger.Info("  - Enter your guess in the textbox")
	logger.Info("  - Press Enter or click Submit to check")
	logger.Info("  - Ctrl+N: Start new game")
	logger.Info("  - Ctrl+H: Get hint (costs 5 points)")
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
