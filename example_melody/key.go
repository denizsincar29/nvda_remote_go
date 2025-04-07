// this is a workaround for my lazyness, i'll do dotenv later
package main

import (
	"fmt"
	"os"
)

// GetKey returns the key from key.txt, or asks the user to enter it if it is not found.
func GetKey() string {
	key, err := os.ReadFile("key.txt")
	if err != nil {
		fmt.Println("Key not found. Please enter your nvda remote key:")
		var input string
		fmt.Scanln(&input)
		err = os.WriteFile("key.txt", []byte(input), 0644)
		if err != nil {
			panic(err)
		}
		return input
	}
	return string(key)
}
