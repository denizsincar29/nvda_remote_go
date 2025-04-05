# nvda_remote_go
a simple library for NVDA remote protocol in Go

## Description
This library provides a simple interface for the NVDA remote protocol, allowing you to connect to an NVDA instance and send commands or receive events. It is designed to be easy to use and integrate into your Go applications.
It is not an official library and is not affiliated with NVDA or its developers. It is a personal project created for educational purposes and to help others who may need to work with the NVDA remote protocol in Go.
It is a work in progress, but it is functional and can be used to connect to an NVDA instance and send commands or receive events.
Unknown events are handled in a generic way, because the protocol is not well explored yet.

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

## Contributing
If you would like to contribute to this project, please feel free to fork the repository and submit a pull request. Any contributions, bug reports, or feature requests are welcome.