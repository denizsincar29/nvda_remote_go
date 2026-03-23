// this is a speech logger example package for an NVDA remote client library.
// Use this package to debug everything in the library and test it.
package main

import (
	"fmt"
	"os"

	// goerror is also my package, but it is not a part of nvda remote client library.
	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
)

func main() {
	// create a new logger
	logger := NewLogger(os.Stdout)
	e := goerror.NewError(logger)

	// Load configuration from .env file
	config := exampleconfig.Load()

	// create a new nvda remote client
	remote, err := nvda_remote_go.NewClient(config.Host, config.Port, config.Key, "master", logger)
	e.Must(err, "Failed to create NVDA remote client")
	defer remote.Close()
	for {
		// check error channel for errors
		select {
		case err := <-remote.Errors():
			e.Must(err, "Error from NVDA remote client")
		// check for events
		case event := <-remote.Events():
			switch e := event.(type) {
			case nvda_remote_go.SpeakPacket:
				spokenText := e.GetSequence()
				priority := e.Priority
				logger.Info(fmt.Sprintf("Spoken text: %s, Priority: %d", spokenText, priority))
			}
		}

	}

}

// GoodBye takes an nvda remote client, sends a goodbye message to the client, and closes the client connection.
func GoodBye(remote *nvda_remote_go.NVDARemoteClient) {
	remote.SendSpeech("Goodbye, it was pleasure to help you!")
	remote.Close()
}
