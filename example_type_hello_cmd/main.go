// This is an example of how to use the nvda remote client library to type "Hello from NVDA remote client" in a command prompt window when someone joins the session.
package main

import (
	"fmt"
	"os"
	"time"

	// goerror is also my package, but it is not a part of nvda remote client library.
	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
)

func main() {
	// create a new logger
	logger := NewLogger(os.Stdout)
	e := goerror.NewError(logger)
	key := GetKey()
	// create a new nvda remote client
	remote, err := nvda_remote_go.NewClient("nvdaremote.ru", nvda_remote_go.DEFAULT_PORT, key, "master", logger)
	e.Must(err, "Failed to create NVDA remote client")
	defer remote.Close()

	logger.Info("Connected to NVDA remote client")
	for {
		// check error channel for errors
		select {
		case err := <-remote.Errors():
			e.Must(err, "Error from NVDA remote client")
		// check for events
		case event := <-remote.Events():
			fmt.Println("Event received:", event)
			switch event.(type) {
			case nvda_remote_go.ClientJoinedPacket:
				// do the task in a goroutine to prevent channel queueing
				go func() {
					fmt.Println("Someone joined the session")
					remote.SendKeystroke("win+R")
					time.Sleep(500 * time.Millisecond)
					remote.TypeString("cmd", 50)
					remote.SendKeystroke("enter")
					time.Sleep(700 * time.Millisecond)
					remote.TypeString("echo Hello from NVDA remote client", 50)
					remote.SendKeystroke("enter")
				}()

			default:
			}
			// no error, continue
		}

	}

}
