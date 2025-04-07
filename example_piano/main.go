package main

import (
	"fmt"
	"os"

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
	remote, err := nvda_remote_go.NewClient("nvdaremote.ru", nvda_remote_go.DEFAULT_PORT, key, "slave", logger)
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
