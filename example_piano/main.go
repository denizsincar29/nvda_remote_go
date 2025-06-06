// this example shows how to make a simple piano using nvda remote client library.
// Connect your NVDA remote addon and this example app to the same server and run this example app.
// For this to work, nvda connects as a master.
// You press a key, and instantly receive a beep sound of the corresponding note.
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
	defer remote.Close()
	logger.Info("Connected to NVDA remote client")
	for {
		select {
		case err := <-remote.Errors():
			e.Must(err, "Error from NVDA remote client")
		// check for events
		case event := <-remote.Events():
			switch e := event.(type) {
			case nvda_remote_go.ClientJoinedPacket:
				fmt.Println("Client joined:", e.ID)
			case nvda_remote_go.ClientLeftPacket:
				fmt.Println("Client left:", e.ID)
			case nvda_remote_go.KeyPacket:
				key, err := e.GetKey()
				if !e.Pressed {
					continue
				}
				if err != nil {
					logger.Error("Failed to get key from event", "error", err)
					continue
				}
				note, ok := keyToNote[key]
				if ok {
					remote.SendBeep(note.ToFreq(), 500)
				}
			}
		}

	}
}
