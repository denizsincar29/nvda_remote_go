// This is an example of how  to use	nvda remote client library to create a simple client that connects to the NVDA remote server and listens for events.
// This example shows how to retrieve value of progress bar of an nvda user.
// NVDA beeps out the progress value of the progress bar.
// For this example to work, you need to set the announce progress bars to "beep" or "beep and speak" by pressing nvda+u.
package main

import (
	"fmt"
	"math"
	"os"

	// goerror is also my package, but it is not a part of nvda remote client library.
	"github.com/denizsincar29/goerror"
	"github.com/denizsincar29/nvda_remote_go"
)

func beepFreqToProgress(beepFreq int) int {
	// 110 * 2 ** (progress /25) = beepFreq
	// convert back
	return int(math.Log2(float64(beepFreq)/110) * 25)
}

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
			// fmt.Println("Event received:", event)
			switch e := event.(type) {
			case nvda_remote_go.BeepPacket:
				// convert beep frequency to progress
				progress := beepFreqToProgress(int(e.Hz))
				// log the progress
				logger.Info(fmt.Sprintf("progress: %d", progress))
			default:
			}
			// no error, continue
		}

	}

}
