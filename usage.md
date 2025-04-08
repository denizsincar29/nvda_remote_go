# A small guide on how to use the NVDA remote library in Go
This guide will let you start using the library in no time. It will cover the basics of how to use the library, how to connect to a server, and how to send and receive messages. It will also cover some advanced topics, such as error handling and message processing.

### Getting started
Asuming you have Go installed, you've read the [readme](readme.md) and you know what NVDA remote is, let's get started.

```go
package main

import (
	"log"
	"time"

	"github.com/denizsincar29/nvda_remote_go"
)

func main(){
	// create a new nvda remote client
	remote, err := nvda_remote_go.NewClient("nvdaremote.ru", nvda_remote_go.DEFAULT_PORT, "my_connection_key", "slave", nil)
	if err != nil {
		log.Fatalf("Failed to create NVDA remote client: %v", err)
	}
	// Important! Always close the client when you're done with it.
	defer remote.Close()

	// main loop
	for {
		// check all channels for any events
		select {
		case err := <-remote.Errors():
			log.Printf("Error from NVDA remote client: %v", err) //Error occurred after sleep
		case eventt := <-remote.Events():
			switch e := event.(type) {
			case nvda_remote_go.ClientJoinedPacket:
				log.Printf("Client joined: %s", e.ID)
			case nvda_remote_go.KeyPacket:
				key, err := e.GetKey()
				if err == nil && event.Pressed {
					remote.SendSpeech("You pressed: " + key)
				}
			default:
				log.Printf("Some other event: %v", e) // some other event
			}
		}
	}
}
```

## explanation of the code
Let's go through the code step by step.
1. We import the necessary packages. We need the `log` package for logging, the `time` package for sleeping, and the `nvda_remote_go` package for using the library.
2. We create a new NVDA remote client using the `NewClient` function. We pass the server address, port, connection key, and client type (in this case, "slave"). We also pass `nil` for the logger, which means we don't want to use a custom logger. You can also pass a custom `*slog.Logger` if you need a single logger for all your needs.
3. We check for errors when creating the client. If there is an error, we log it and exit the program. Remember, only the initializer can return an error. All other errors are sent to the error channel.
4. We defer the `Close` method to ensure that the client is closed when we're done with it. This is important to avoid memory leaks and other issues.
5. We enter the main loop. This is where we check for events and handle them accordingly.

The communication with the library is done through channels. The library has two channels: `Errors` and `Events`. The `Errors` channel is used to receive errors that occur during the communication with the server. The `Events` channel is used to receive all client's messages.
All socket work is done in 2 goroutines. One goroutine is used to send messages to the server, and the other goroutine is used to receive the messages. This allows us to send and receive messages simultaneously without blocking the main thread.
To check both channels for any events, we use a `select` statement. The `select` statement allows us to wait for multiple channels to be ready. In this case, we wait for either the `Errors` channel or the `Events` channel to be ready.
The most interesting part is the events channel.
An event is a struct that contains the type of event and the data associated with it. The library has several types of events, such as `ClientJoinedPacket`, `KeyPacket`, and `SendClipboardPacket`. Each event has its own struct that contains the data associated with it.
We use a type assertion / switch to check the type of the event. The rest is self-explanatory.
To send a message to the server, we use one of the Send* methods. For example, to send a speech message, we use the `SendSpeech` method. This method takes a string as an argument and sends it to the server. The server will then relay the message to the target client.
- `SendSpeech("text-)` sends a speech message from the target to the controller. A controller can't send speech.
- `SendClipboard("text")` sends a clipboard message from the target to the controller or back. The text argument is the text to be sent to the clipboard.
- `SendBeep(frequency, duration)` sends a beep message from the target to the controller. The frequency argument is the frequency of the beep in hertz, and the duration argument is the duration of the beep in milliseconds. This is used to also hear the beeps from the target.
- - `SendBraille(data)` sends a braille message from the target to the controller. The data argument is the data to be sent to the braille display.
- `SendSAS()` sends ctrl+alt+delete keystroke from the target to the controller. This is used to access the task manager or lock the computer.
- `SendKey("keyname", pressed bool)` sends a key press from controller to target. The key name is the name of the key, such as "a", "b", "c", etc. The pressed argument is a boolean value that indicates whether the key is pressed or released.
- `SendKeystroke("ctrl+shift+a")` sends a keystroke from controller to target. The keystroke argument is the keystroke to be sent, such as "ctrl+shift+a". This is used to send a combination of keys. This function internally calls `SendKey` for each key press and makes little delay between them, so it is recommended to use a goroutine for subsequent calls to this function.

You can't send mouce events, because blind people usually don't use mouce.

### Recommendations
1. Don't block the thread that receives messages from the channels. For sleepy functions, use temporary goroutines. Check out `./example_type_hello_cmd`, there a goroutine is created and run for a group of subsequent keystrokes and time.Sleeps.
2. Don't use SendKey method unless you know what you're doing. This method is usually able to make you forget about the pressed key and not send the `pressed=false` counterpart. SendKeystroke is the recommended way to send keys and keystrokes, though it is recommended to run it in a goroutine.
3. Don't forget to close the client with `defer remote.Close()`. This method closes the connection and all channels, waits for both goroutines to finish and cleans up the memory. It is important to call this method when you're done with the client.
4. Don't forget to check for errors in the error channel. This is important to avoid crashes and other issues (mainly with tcp communication).