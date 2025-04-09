// this is a main example package for an NVDA remote client library.
// Use this package to debug everything in the library and test it.
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
	remote, err := nvda_remote_go.NewClientBuilder().
		WithHost("nvdaremote.ru").
		WithChannel(key).
		AsSlave().
		WithLogger(logger).
		Build()
	e.Must(err, "Failed to create NVDA remote client")
	// defer remote.Close()  // we'd do this, but lets defer goodbye instead
	defer GoodBye(remote)
	err = remote.CheckServer()
	e.Must(err, "Failed to check server verification")
	if !remote.State().IsTrusted() {
		if remote.VerificationStatus().IsUnknown() {
			logger.Warn("Permanently trusting server", "fingerprint", remote.ServerFingerprint())
			err = remote.Trust()
			e.Must(err, "Failed to trust server")
		} else {
			logger.Warn("Server verification error", "status", remote.VerificationStatus().StatusMessage())
			return
		}
	}
	err = remote.Connect()
	e.Must(err, "Failed to connect to NVDA remote client")
	logger.Info("Connected to NVDA remote client")
	ticker := time.NewTicker(5 * time.Second)
	for {
		// check error channel for errors
		select {
		case err := <-remote.Errors():
			e.Must(err, "Error from NVDA remote client")
		// check for events
		case event := <-remote.Events():
			fmt.Println("Event received:", event)
		case <-ticker.C:
			remote.SendSpeech("Hello, nvda user! I'm a fake nvda remote client.")
		}

	}

}

// GoodBye takes an nvda remote client, sends a goodbye message to the client, and closes the client connection.
func GoodBye(remote *nvda_remote_go.NVDARemoteClient) {
	remote.SendSpeech("Goodbye, it was pleasure to help you!")
	remote.Close()
}
