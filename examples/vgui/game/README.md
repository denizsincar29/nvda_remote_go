# Number Guessing Game Example

An interactive number guessing game with audio feedback.

## Gameplay

- The computer thinks of a number between 1 and 100
- You have 7 attempts to guess the correct number
- After each guess, you'll get feedback:
  - "Too low, go higher/much higher/a little higher"
  - "Too high, go lower/much lower/a little lower"
- Audio tones provide additional feedback:
  - Low tone (400 Hz) for too low
  - High tone (800 Hz) for too high
  - Success tone when you win
  - Game over tone when you lose

## Features

- **TextBox Input**: Type your guess
- **Smart Hints**: Get directional feedback and range hints
- **Audio Feedback**: Tones indicate if guess is high or low
- **Score System**: Earn points for winning with fewer attempts
- **Hint System**: Get range hints (costs 5 points)
- **Play Again**: Quick restart with Ctrl+N

## Usage

1. Ensure NVDA remote server is running
2. Configure your connection settings
3. Run the example:
   ```bash
   go run .
   ```
4. Connect with a controller client
5. Tab to the guess input box
6. Type a number between 1 and 100
7. Press Enter to submit your guess

## Controls

- **Tab**: Navigate between elements
- **Type number**: Enter your guess in textbox
- **Enter**: Submit guess (activates Submit button)
- **Ctrl+N**: Start new game
- **Ctrl+H**: Get hint (costs 5 points)

## Buttons

- **Submit Guess**: Check your guess (default button, Enter key)
- **New Game**: Start a fresh game (Ctrl+N)
- **Get Hint**: Reveal which quarter the number is in (Ctrl+H)

## Scoring

- Win with fewer attempts = more points
- Points awarded: (8 - attempts) × 10
- Example: Win in 3 attempts = 50 points
- Hints cost 5 points each

## Screen Reader Announcements

- Current guess number and result after each attempt
- Helpful hints like "try a little higher" or "try much lower"
- Attempts remaining
- Score updates
- Victory/defeat messages
- Audio tones for immediate feedback

## Strategy Tips

1. Start with 50 (middle of range)
2. Use binary search strategy
3. Listen to the hints carefully
4. Pay attention to audio tones
5. Use hints sparingly to preserve score

## Implementation Notes

This example demonstrates:

1. **TextBox Input**: Single-line text input for guesses
2. **Game State**: Tracking attempts, score, game over
3. **Random Numbers**: Generating target number
4. **Audio Feedback**: Using SendTone for sound effects
5. **Dynamic Labels**: Updating status messages
6. **Default Button**: Enter key submits guess
7. **Hotkeys**: Quick access to game functions
8. **Input Validation**: Checking guess is valid number in range
9. **Hint System**: Optional help with penalty

## Audio Tones

- **Low Guess** (400 Hz, 100ms): Your guess is too low
- **High Guess** (800 Hz, 100ms): Your guess is too high
- **Game Over** (200 Hz, 300ms): You've run out of attempts
- **New Game** (600 Hz, 100ms): Fresh game started
