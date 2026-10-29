package nvda_remote_go

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestServerActsAsSlave checks the whole point of server mode: a master client
// connects to us directly and we answer it as the controled (slave) machine.
func TestServerActsAsSlave(t *testing.T) {
	const channel = "test-channel"

	srv, err := NewServer("127.0.0.1", "0", channel, testLogger())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	master, err := NewClient(host, port, channel, connTypeMaster, testLogger())
	if err != nil {
		t.Fatalf("connect master: %v", err)
	}
	defer master.Close()

	// 1. The master must see us as a slave in the channel.
	deadline := time.After(5 * time.Second)
	joined := false
	for !joined {
		select {
		case ev := <-master.Events():
			if cj, ok := ev.(ChannelJoinedPacket); ok {
				if len(cj.Clients) != 1 || cj.Clients[0].ID != serverSelfID || cj.Clients[0].ConnectionType != connTypeSlave {
					t.Fatalf("unexpected channel_joined payload: %+v", cj)
				}
				if len(cj.UserIDs) != 1 || cj.UserIDs[0] != serverSelfID {
					t.Fatalf("unexpected user_ids: %+v", cj.UserIDs)
				}
				joined = true
			}
		case err := <-master.Errors():
			t.Fatalf("master error: %v", err)
		case <-deadline:
			t.Fatal("timeout waiting for channel_joined")
		}
	}

	// 2. A key pressed on the master must reach us directly.
	if err := master.Send(newTestKeyPacket(t)); err != nil {
		t.Fatalf("send key: %v", err)
	}
	select {
	case ev := <-srv.Events():
		kp, ok := ev.(KeyPacket)
		if !ok {
			t.Fatalf("expected KeyPacket, got %T", ev)
		}
		if kp.Origin == nil || *kp.Origin == 0 {
			t.Fatalf("key packet has no origin: %+v", kp)
		}
		if kp.VKCode == 0 {
			t.Fatalf("key packet has no vk code: %+v", kp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for key packet on the server")
	}

	// 3. Speech/beeps sent by us must arrive at the master, stamped with our id.
	srv.SendBeep(440, 250)
	select {
	case ev := <-master.Events():
		bp, ok := ev.(BeepPacket)
		if !ok {
			t.Fatalf("expected BeepPacket, got %T", ev)
		}
		if bp.Hz != 440 || bp.Length != 250 {
			t.Fatalf("unexpected beep: %+v", bp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for beep on the master")
	}
}

// TestServerRejectsWrongChannel makes sure a master cannot join a foreign
// channel when the server is configured with a fixed one.
func TestServerRejectsWrongChannel(t *testing.T) {
	srv, err := NewServer("127.0.0.1", "0", "right-channel", testLogger())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	host, port, _ := net.SplitHostPort(srv.Addr())
	master, err := NewClient(host, port, "wrong-channel", connTypeMaster, testLogger())
	if err != nil {
		t.Fatalf("connect master: %v", err)
	}
	defer master.Close()

	select {
	case ev := <-master.Events():
		if _, ok := ev.(ChannelJoinedPacket); ok {
			t.Fatalf("master joined despite wrong channel")
		}
	case <-time.After(2 * time.Second):
		// expected: no channel_joined, connection is closed by the server
	}
}

func newTestKeyPacket(t *testing.T) Packet {
	t.Helper()
	kp, err := NewKeyPacket("a", true)
	if err != nil {
		t.Fatalf("build key packet: %v", err)
	}
	return kp
}
