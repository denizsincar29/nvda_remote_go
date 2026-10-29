package nvda_remote_go

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestSessionStorePersists is the point of sessions: context survives a
// restart, keyed by the channel (the user's nickname).
func TestSessionStorePersists(t *testing.T) {
	dir := t.TempDir()

	store1, err := NewSessionStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s1 := store1.Session("alice")
	if err := s1.Set("visits", 3); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s1.Set("history", []string{"hi", "there"}); err != nil {
		t.Fatalf("set history: %v", err)
	}
	if err := s1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	store2, err := NewSessionStore(dir)
	if err != nil {
		t.Fatalf("store 2: %v", err)
	}
	s2 := store2.Session("alice")
	var visits int
	if err := s2.Get("visits", &visits); err != nil || visits != 3 {
		t.Fatalf("visits = %d, err = %v", visits, err)
	}
	var history []string
	if err := s2.Get("history", &history); err != nil || len(history) != 2 {
		t.Fatalf("history = %v, err = %v", history, err)
	}
	if err := s2.Get("missing", &visits); !errors.Is(err, ErrNoValue) {
		t.Fatalf("expected ErrNoValue, got %v", err)
	}
	if keys := store2.Keys(); len(keys) != 1 || keys[0] != "alice" {
		t.Fatalf("keys = %v", keys)
	}
}

// TestServerKeepsPerChannelSessions checks that the server hands every master
// its own session and its own private packet stream.
func TestServerKeepsPerChannelSessions(t *testing.T) {
	store, err := NewSessionStore(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	srv, err := NewServerWithOptions(ServerOptions{
		Host:     "127.0.0.1",
		Port:     "0",
		Logger:   testLogger(),
		Sessions: store,
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer srv.Close()

	type joinRec struct {
		nick    string
		id      int
		session *Session
	}
	joins := make(chan joinRec, 4)
	packets := make(chan string, 16)

	srv.SetJoinHandler(func(info JoinInfo) {
		joins <- joinRec{nick: info.Channel, id: info.ClientID, session: info.Session}
		// Per-user greeting, like the chat example does.
		if info.Session != nil {
			_ = info.Session.Set("visits", 1)
			srv.SendSpeechTo(info.ClientID, "welcome "+info.Channel)
		}
	})
	srv.SetPacketHandler(func(clientID int, p Packet) {
		if nick, ok := srv.ChannelByClientID(clientID); ok {
			packets <- nick
		}
	})

	host, port, _ := net.SplitHostPort(srv.Addr())

	alice, err := NewClient(host, port, "alice", connTypeMaster, testLogger())
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	defer alice.Close()
	bob, err := NewClient(host, port, "bob", connTypeMaster, testLogger())
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	defer bob.Close()

	seen := map[string]*Session{}
	for i := 0; i < 2; i++ {
		select {
		case rec := <-joins:
			if rec.session == nil {
				t.Fatalf("no session for %s", rec.nick)
			}
			seen[rec.nick] = rec.session
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for joins")
		}
	}
	if seen["alice"] == seen["bob"] {
		t.Fatal("both users got the same session")
	}

	// Alice's speech must arrive at Alice, not at Bob.
	gotSpeech := false
	deadline := time.After(5 * time.Second)
	for !gotSpeech {
		select {
		case ev := <-alice.Events():
			sp, ok := ev.(SpeakPacket)
			if !ok {
				continue // channel_joined and friends
			}
			if sp.GetSequence() == "" {
				t.Fatal("empty speech")
			}
			gotSpeech = true
		case <-deadline:
			t.Fatal("alice got no greeting")
		}
	}
	select {
	case ev := <-bob.Events():
		if sp, ok := ev.(SpeakPacket); ok && sp.GetSequence() == "[welcome alice]" {
			t.Fatal("bob received alice's private speech")
		}
	case <-time.After(300 * time.Millisecond):
		// expected: nothing for bob from alice's greeting
	}

	// Packets are routed with the sender's channel.
	kp, _ := NewKeyPacket("a", true)
	if err := alice.Send(kp); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case nick := <-packets:
		if nick != "alice" {
			t.Fatalf("packet attributed to %q", nick)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}
