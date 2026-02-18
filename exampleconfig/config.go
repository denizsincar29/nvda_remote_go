// Package exampleconfig provides common configuration loading for NVDA Remote examples.
// It loads configuration from .env file using godotenv and provides fallback mechanisms.
package exampleconfig

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config holds the configuration for NVDA Remote examples
type Config struct {
	Key  string
	Host string
	Port string
}

const (
	// DefaultHost is the default NVDA Remote server host
	DefaultHost = "nvdaremote.ru"
	// DefaultPort is the default NVDA Remote server port (as a string for compatibility with client.NewClient)
	DefaultPort = "6837"
)

// Load loads configuration from .env file and environment variables.
// If the key is not found, it prompts the user to enter it and saves it to key.txt.
// Returns a Config struct with Key, Host, and Port.
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if file doesn't exist)
	_ = godotenv.Load()

	config := &Config{
		Key:  getKey(),
		Host: getHost(),
		Port: getPort(),
	}

	return config, nil
}

// getKey returns the key from environment variable, key.txt file, or prompts the user.
func getKey() string {
	// First check environment variable
	if key := os.Getenv("NVDA_REMOTE_KEY"); key != "" {
		return key
	}

	// Try to read from key.txt
	key, err := os.ReadFile("key.txt")
	if err == nil && len(key) > 0 {
		return string(key)
	}

	// Prompt user for key
	fmt.Println("Key not found. Please enter your NVDA remote key:")
	var input string
	fmt.Scanln(&input)

	// Save key to key.txt for future use
	err = os.WriteFile("key.txt", []byte(input), 0644)
	if err != nil {
		fmt.Printf("Warning: Failed to save key to key.txt: %v\n", err)
	}

	return input
}

// getHost returns the host from environment variable or uses default
func getHost() string {
	if host := os.Getenv("NVDA_REMOTE_HOST"); host != "" {
		return host
	}
	return DefaultHost
}

// getPort returns the port from environment variable or uses default
func getPort() string {
	if port := os.Getenv("NVDA_REMOTE_PORT"); port != "" {
		return port
	}
	return DefaultPort
}
