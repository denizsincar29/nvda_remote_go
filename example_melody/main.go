package main

import (
	"fmt"
	"os"

	// goerror is also my package, but it is not a part of nvda remote client library.
	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	"github.com/denizsincar29/nvda_remote_go/fingerprints"
)

func main() {
	// create a new logger
	logger := NewLogger(os.Stdout)
	e := goerror.NewError(logger)
	key := GetKey()
	// create a new nvda remote client
	fmConfig := fingerprints.Config{Directory: "", AppName: "NVDARemoteExamples"}
	fm, err := fingerprints.NewFingerprintManager(fmConfig)
	e.Must(err, "Failed to create fingerprint manager")
	remote, err := nvda_remote_go.NewClient("nvdaremote.ru", nvda_remote_go.DEFAULT_PORT, key, "slave", logger, fm)
	e.Must(err, "Failed to create NVDA remote client")
	// defer remote.Close()  // we'd do this, but lets defer goodbye instead
	defer GoodBye(remote)
	logger.Info("Connected to NVDA remote client")
	notemaker := NewNoteMaker()
	notch := notemaker.Ch
	for {
		// check error channel for errors
		select {
		case err := <-remote.Errors():
			e.Must(err, "Error from NVDA remote client")
		// check for events
		case event := <-remote.Events():
			fmt.Println("Event received:", event)
			switch e := event.(type) {
			case nvda_remote_go.KeyPacket:
				key, err := e.GetKey()
				if err != nil {
					logger.Error("Failed to get key from event", "error", err)
					continue
				}
				if e.Pressed && key == "space" {
					notemaker.Start()
				}
			case nvda_remote_go.ClientJoinedPacket:
				notemaker.Start()
			}
		case note, ok := <-notch:
			if !ok {
				logger.Info("Channel closed, strange!")
				return
			}
			remote.SendBeep(note.Freq, note.Duration)
		}

	}

}

// GoodBye takes an nvda remote client, sends a goodbye message to the client, and closes the client connection.
func GoodBye(remote *nvda_remote_go.NVDARemoteClient) {
	remote.SendSpeech("Goodbye, it was pleasure to help you!")
	remote.Close()
}
