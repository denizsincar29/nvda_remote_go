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

### Virtual GUI (vgui) Module
The library includes a powerful **vgui** (virtual GUI) package that enables creating accessible remote interfaces. With vgui, you can build virtual GUI elements (buttons, listboxes, checkboxes) that are navigated via keyboard and spoken to the user through NVDA remote protocol. This is perfect for creating remote configuration interfaces, menus, forms, and interactive applications. See the [vgui documentation](vgui/README.md) and [examples/vgui/simple_form](examples/vgui/simple_form/) for details.

## Purpose of this library
This library is intended to be used by developers who want to create applications that can interact with NVDA remote. It provides a simple and easy-to-use interface for sending and receiving messages, as well as handling errors and other events.
Personally, I created this library for fun, to explore the protocol and make little experiments with it. All my experiments are in the repo, feal free to check them out.

## Server mode (no relay)

Normally a session needs three parties: master, relay and slave. In server mode
your app speaks the relay protocol itself and acts as the controled (slave)
machine, so the master connects straight to you — one hop less per keystroke
and per speech message.

```go
srv, err := nvda_remote_go.NewServer("0.0.0.0", "6837", "my-channel", logger)
defer srv.Close()

for ev := range srv.Events() {
    if kp, ok := ev.(nvda_remote_go.KeyPacket); ok {
        // key from the master arrived directly
    }
}
srv.SendSpeech("hello from the server side")
```

- `NewServer` listens with TLS and generates a self signed certificate in
  memory; use `NewServerWithTLSConfig` to supply your own.
- The server presents itself as `slave` with id `1`, so an NVDA master sees a
  normal slave in the channel list.
- Pass an empty channel to accept any channel the master sends.
- `Send*` helpers (speech, beep, braille, keys) are the same as on the client —
  both types embed the same `packetSender`.
- Examples can run either way: `examples/audio/piano` uses
  `NVDA_REMOTE_MODE=server NVDA_SERVER_PORT=6837 NVDA_SERVER_CHANNEL=key`.

### Sessions (server mode only)

A relay cannot keep state for its clients, but when your app is the server it
can remember things per channel — for a chat, the channel is the user's
nickname.

```go
store, _ := nvda_remote_go.NewSessionStore("~/.config/nvda_remote_go/sessions")
srv, _ := nvda_remote_go.NewServerWithOptions(nvda_remote_go.ServerOptions{
    Port: "6837", Sessions: store,
})

srv.SetJoinHandler(func(info nvda_remote_go.JoinInfo) {
    var visits int
    _ = info.Session.Get("visits", &visits) // ErrNoValue on first join
    _ = info.Session.Set("visits", visits+1)
    srv.SendSpeechTo(info.ClientID, "welcome back")
})

srv.SetPacketHandler(func(clientID int, p nvda_remote_go.Packet) {
    nick, _ := srv.ChannelByClientID(clientID)
    // every user gets their own stream, so one GUI per client is possible
})
```

- `Session` is a small JSON key/value store; `Save` writes it atomically to
  `<dir>/<channel>.json`, `NewSessionStore(dir)` loads it back on restart.
- Per client sending: `SendToClient`, `SendToChannel`, `SendSpeechTo`,
  `CancelSpeechTo`, `SendBeepTo`, `ClientsInChannel`, `ChannelByClientID`.
- Sessions are flushed when a client leaves and when the server closes.

## Installation
```bash
go get github.com/denizsincar29/nvda_remote_go
```

## Configuration for Examples
The examples in this repository now support configuration through environment variables or a `.env` file.

### Configuration Options
- `NVDA_REMOTE_KEY` - Your NVDA remote key (required)
- `NVDA_REMOTE_HOST` - NVDA Remote server host (optional, defaults to `nvdaremote.ru`)
- `NVDA_REMOTE_PORT` - NVDA Remote server port (optional, defaults to `6837`)

### Setting up Configuration
Run the interactive setup script:
```bash
./setup.sh
```

This will guide you through the configuration process and create a `.env` file with your settings.

Alternatively, you can set environment variables directly or the examples will prompt you for the key if not found.

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

## Examples
All examples now use a common configuration mechanism that loads settings from `.env` files or environment variables. See the [Configuration for Examples](#configuration-for-examples) section above.

The examples are now organized in the `examples/` directory. See [examples/README.md](examples/README.md) for detailed information.

### Quick Overview
- **examples/basic/main_example** - Simple example that sends speech messages every 5 seconds
- **examples/audio/melody** - Plays a melody when spacebar is pressed
- **examples/audio/piano** - Interactive piano using key presses
- **examples/controller/type_hello_cmd** - Controller that types commands remotely
- **examples/basic/tell_progress** - Listens for progress bar beep events
- **examples/vgui/simple_form** - Virtual GUI form with listboxes, checkboxes, and buttons

To run an example:
```bash
cd examples/vgui/simple_form
go run .
```

## Usage
The usage of this library is described in the [usage](usage.md) file. Check it out for more details on how to use the library and its features.

## Contributing
If you would like to contribute to this project, please feel free to fork the repository and submit a pull request. Any contributions, bug reports, or feature requests are welcome.