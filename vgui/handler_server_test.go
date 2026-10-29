package vgui_test

import (
	"io"
	"os"
	"log/slog"
	"net"
	"testing"
	"time"

	nvda "github.com/denizsincar29/nvda_remote_go"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestHandlerWorksAsServer is the whole point of the Remote interface: a
// virtual GUI driven by our own server, with a master connecting straight to
// it. Master presses Tab -> handler moves focus -> speech flies back.
func TestHandlerWorksAsServer(t *testing.T) {
	const channel = "vgui-server-test"

	srv, err := nvda.NewServer("127.0.0.1", "0", channel, quietLogger())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	gui := vgui.NewGUI()
	gui.AddElement(vgui.NewLabel("first"))
	gui.AddElement(vgui.NewButton("second"))

	h := vgui.NewHandler(srv, gui, quietLogger())
	h.Start()
	defer h.Stop()

	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	master, err := nvda.NewClient(host, port, channel, "master", quietLogger())
	if err != nil {
		t.Fatalf("connect master: %v", err)
	}
	defer master.Close()

	// Wait until the master is in the channel, then press Tab.
	joined := false
	deadline := time.After(5 * time.Second)
	for !joined {
		select {
		case ev := <-master.Events():
			if _, ok := ev.(nvda.ChannelJoinedPacket); ok {
				joined = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for channel_joined")
		}
	}

	tabKeys := []string{"tab", "tab"}
	for _, k := range tabKeys {
		kp, err := nvda.NewKeyPacket(k, true)
		if err != nil {
			t.Fatalf("key packet: %v", err)
		}
		if err := master.Send(kp); err != nil {
			t.Fatalf("send key: %v", err)
		}
		release, _ := nvda.NewKeyPacket(k, false)
		_ = master.Send(release)
	}

	// The server should answer with speech (focus announcement).
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev := <-master.Events():
			sp, ok := ev.(nvda.SpeakPacket)
			if !ok {
				continue
			}
			if sp.GetSequence() == "" {
				t.Fatalf("empty speech packet: %+v", sp)
			}
			return // got speech, the round trip works
		case <-timeout:
			t.Fatal("timeout waiting for speech from the vgui server")
		}
	}
}

// TestCertIsStable makes sure the server keeps the same certificate between
// restarts instead of generating a new identity every launch.
func TestCertIsStable(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/server.crt"
	keyFile := dir + "/server.key"

	s1, err := nvda.NewServerWithCertFiles("127.0.0.1", "0", "c", certFile, keyFile, quietLogger())
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	first := readFile(t, certFile)
	s1.Close()

	s2, err := nvda.NewServerWithCertFiles("127.0.0.1", "0", "c", certFile, keyFile, quietLogger())
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	defer s2.Close()

	if again := readFile(t, certFile); string(again) != string(first) {
		t.Fatal("certificate changed between restarts")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
