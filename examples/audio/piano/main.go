// this example shows how to make a simple piano using nvda remote client library.
// There are two ways to run it:
//
//  1. Client mode (default): connect the addon and this app to the same relay
//     server (nvdaremote.ru or your own), this app joins as a slave.
//     Set NVDA_REMOTE_KEY / NVDA_REMOTE_HOST / NVDA_REMOTE_PORT as usual.
//
//  2. Server mode: this app IS the server, no relay in the middle.
//     NVDA_REMOTE_MODE=server NVDA_SERVER_PORT=6837 NVDA_SERVER_CHANNEL=mykey go run .
//     Then in NVDA Remote connect as master to <your host>:6837 with that key.
//     Keystrokes travel straight to this process, so there is one hop less.
//
// For this to work, nvda connects as a master.
// You press a key, and instantly receive a beep sound of the corresponding note.
package main

import (
	"fmt"
	"os"

	// goerror is also my package, but it is not a part of nvda remote client library.
	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
	exampleconfig "github.com/denizsincar29/nvda_remote_go/examples/shared/config"
)

// remote is the part of the API both the client and the server expose.
type remote interface {
	Events() <-chan nvda_remote_go.Packet
	Errors() <-chan error
	SendBeep(hz float64, length int, left ...int)
	Close()
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	// create a new logger
	logger := NewLogger(os.Stdout)
	e := goerror.NewError(logger)

	// Load configuration from .env file
	config := exampleconfig.Load()

	var rm remote

	if os.Getenv("NVDA_REMOTE_MODE") == "server" {
		// Server mode: we speak the protocol ourselves, the master connects here.
		host := envOr("NVDA_SERVER_HOST", "0.0.0.0")
		port := envOr("NVDA_SERVER_PORT", "6837")
		channel := envOr("NVDA_SERVER_CHANNEL", config.Key)

		srv, err := nvda_remote_go.NewServer(host, port, channel, logger)
		e.Must(err, "Failed to start NVDA remote server")
		rm = srv
		logger.Info("Running as server", "address", srv.Addr(), "channel", channel)
	} else {
		// create a new nvda remote client
		client, err := nvda_remote_go.NewClient(config.Host, config.Port, config.Key, "slave", logger)
		e.Must(err, "Failed to create NVDA remote client")
		rm = client
		logger.Info("Connected to NVDA remote client")
	}
	defer rm.Close()

	for {
		select {
		case err := <-rm.Errors():
			e.Must(err, "Error from NVDA remote")
		// check for events
		case event := <-rm.Events():
			switch ev := event.(type) {
			case nvda_remote_go.ClientJoinedPacket:
				fmt.Println("Client joined:", ev.ID)
			case nvda_remote_go.ClientLeftPacket:
				fmt.Println("Client left:", ev.ID)
			case nvda_remote_go.KeyPacket:
				key, err := ev.GetKey()
				if !ev.Pressed {
					continue
				}
				if err != nil {
					logger.Error("Failed to get key from event", "error", err)
					continue
				}
				note, ok := keyToNote[key]
				if ok {
					rm.SendBeep(note.ToFreq(), 500)
				}
			}
		}

	}
}
