# nvda_remote_go
a simple library for NVDA remote protocol in Go

## what is NVDA remote?
NVDA remote is an NVDA addon that allows you to control other computers using NVDA. Think of it as a remote desktop solution for NVDA users.
Usually NVDA remote works through server and 2 clients - a controller and target.
The controller sends keystrokes to the target through the relay server, target client virtually presses the keys, NVDA of the target computer speaks the actions he performed and all speech is sent back to the controller through the relay server.
The target can send back to the controller not only speech, but beeps with different frequencies and lengths, sounds and braille messages.
Additionally both clients can send eachother his clipboard.

## What is this library for?
This library is an NVDA remote client written in Go. It allows you to connect to an NVDA remote server as a controller or a target. It can send all kinds of messages to the server that are relayed to the target or controller, respectively. It can also receive messages from the server and process them accordingly.

## Purpose of this library
This library is intended to be used by developers who want to create applications that can interact with NVDA remote. It provides a simple and easy-to-use interface for sending and receiving messages, as well as handling errors and other events.
Personally, I created this library for fun, to explore the protocol and make little experiments with it. All my experiments are in the repo, feal free to check them out.

## Installation
```bash
go get github.com/denizsincar29/nvda_remote_go
```
## Usage
Check out the main/main.go file for an example of how to use the library.
Or for a simpler example, check out the code below:
```go
package main

import (
    "log"
    "time"

    "github.com/denizsincar29/nvda_remote_go"
)

func main() {
    key := "your_key_here" // Replace with your actual key
    remote, err := nvda_remote_go.NewClient("nvdaremote.ru", nvda_remote_go.DEFAULT_PORT, key, "slave")
    if err != nil {
        log.Fatalf("Failed to create NVDA remote client: %v", err)
    }
    defer remote.Close()

    log.Println("Connected to NVDA remote client")

    time.Sleep(5 * time.Second)

    remote.SendSpeech("Hello, NVDA user! This is a test message.")

    // Check for errors in the error channel
    select {
    case err := <-remote.Errors():
        log.Printf("Error from NVDA remote client: %v", err) //Error occurred after sleep
    default:
        // No error in the channel
        log.Println("No error reported.")
    }

    log.Println("Disconnecting") // added indication of disconnection
}

```

## examples
- ./example_main - a simple example program that connects as a target and sends a speech message every 5 seconds while checking and printing events from the controller.
- ./example_melody - a simple example program that connects as a target, checks for spacebar key press event from the controller and sends different beeps at there corresponding times to make a melody.
- ./example_piano - an example target client that receives key press events and sends a beep with a frequency based on the key that was pressed. This example caused me believe that Go is fast! My previous implementation in python was slow, the beep feetback was delayed. Now, it is instant!
- ./example_type_hello_cmd - an example controller client that waits for a target to join, then sends key win+r, cmd, enter, echo hello, enter to the target. This example caused a lot of fun with deadlocks and sleepy goroutines, but finally i fixed it.
- ./example_tell_progress - an example controller client that receives beep events from the target, converts them to a progress bar percentage and logs it to the console. It works only if you set progress bar announcements to beeps or beeps+speech in your NVDA settings.

## Usage
The usage of this library is described in the [usage](usage.md) file. Check it out for more details on how to use the library and its features.

## Contributing
If you would like to contribute to this project, please feel free to fork the repository and submit a pull request. Any contributions, bug reports, or feature requests are welcome.