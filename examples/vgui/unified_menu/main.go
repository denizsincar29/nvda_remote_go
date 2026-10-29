// Command vgui runs the unified virtual GUI demo.
// Client mode (default) connects to a relay; NVDA_REMOTE_MODE=server makes it
// the server itself, so the master connects straight here.
package main

import "github.com/denizsincar29/nvda_remote_go/examples/vgui/app"

func main() {
	app.Main()
}
