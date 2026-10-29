// Command chat is a virtual chat that runs as its own NVDA Remote server.
//
// Every user connects as a master with their nickname as the key, so the
// channel name doubles as the login. The server keeps a session per nickname
// (history, unread messages, visit counter) on disk, which means a user gets
// their context back when they reconnect — something a plain relay client can
// never do.
//
// Run it:
//
//	NVDA_REMOTE_MODE=server NVDA_SERVER_PORT=6837 go run ./examples/vgui/chat
//
// Then in NVDA Remote connect as a master to <host>:6837 using your nickname as
// the key. Type a message in the "Message" box and press Enter to send it to
// everyone else; Up/Down in the "History" list reads what came before.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nvda "github.com/denizsincar29/nvda_remote_go"
	"github.com/denizsincar29/nvda_remote_go/vgui"
)

const (
	historyLimit = 200
	unreadSpeech = 5
)

// ChatMessage is one stored line of the conversation.
type ChatMessage struct {
	From string    `json:"from"`
	Text string    `json:"text"`
	Time time.Time `json:"time"`
}

func (m ChatMessage) line() string {
	return m.From + ": " + m.Text
}

// user is one connected master with their own GUI and session.
type user struct {
	id      int
	nick    string
	session *nvda.Session
	gui     *vgui.GUI
	handler *vgui.Handler
	box     *vgui.TextBox
	list    *vgui.ListBox

	history []ChatMessage
	pending []ChatMessage
	visits  int
}

type chat struct {
	srv    *nvda.NVDARemoteServer
	logger *slog.Logger

	mu    sync.Mutex
	users map[int]*user
}

// boundRemote sends speech to one particular client of the server, so every
// user hears their own interface and not a broadcast of everyone else's.
type boundRemote struct {
	srv *nvda.NVDARemoteServer
	id  int
}

func (b boundRemote) SetEventHandler(func(nvda.Packet)) {}
func (b boundRemote) SendSpeech(text string, priority ...int) {
	b.srv.SendSpeechTo(b.id, text, priority...)
}
func (b boundRemote) CancelSpeech() { b.srv.CancelSpeechTo(b.id) }

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if os.Getenv("NVDA_REMOTE_MODE") != "server" {
		fmt.Fprintln(os.Stderr, "this example only runs as a server:")
		fmt.Fprintln(os.Stderr, "  NVDA_REMOTE_MODE=server NVDA_SERVER_PORT=6837 go run ./examples/vgui/chat")
		os.Exit(2)
	}

	host := envOr("NVDA_SERVER_HOST", "0.0.0.0")
	port := envOr("NVDA_SERVER_PORT", "6837")
	sessionsDir := envOr("NVDA_CHAT_SESSIONS", defaultSessionsDir())

	store, err := nvda.NewSessionStore(sessionsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "session store:", err)
		os.Exit(1)
	}
	logger.Info("Sessions are kept in", "dir", store.Dir())

	// Empty channel: any key is accepted and becomes the nickname.
	srv, err := nvda.NewServerWithOptions(nvda.ServerOptions{
		Host: host, Port: port, Logger: logger, Sessions: store,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
	defer srv.Close()

	c := &chat{srv: srv, logger: logger, users: make(map[int]*user)}
	srv.SetJoinHandler(c.onJoin)
	srv.SetLeaveHandler(c.onLeave)
	srv.SetPacketHandler(c.onPacket)

	logger.Info("Chat server ready", "address", srv.Addr())

	select {} // serve until killed
}

func defaultSessionsDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "chat-sessions"
	}
	return filepath.Join(dir, "nvda_remote_go", "chat")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// onJoin builds a private GUI for the new master and restores their session.
func (c *chat) onJoin(info nvda.JoinInfo) {
	nick := info.Channel
	if nick == "" {
		nick = fmt.Sprintf("user%d", info.ClientID)
	}

	u := &user{id: info.ClientID, nick: nick, session: info.Session}
	if info.Session != nil {
		_ = info.Session.Get("history", &u.history)
		_ = info.Session.Get("pending", &u.pending)
		_ = info.Session.Get("visits", &u.visits)
	}
	u.visits++

	gui := vgui.NewGUI()
	u.gui = gui

	u.list = vgui.NewListBox("History", historyLines(u.history))
	gui.AddElement(u.list)

	u.box = vgui.NewTextBox("Message", "")
	gui.AddElement(u.box)

	send := vgui.NewButton("Send")
	send.OnClick = func() string { return c.send(u) }
	gui.AddElement(send)
	gui.SetDefaultButton(send)
	gui.SetFocus(u.box) // start where typing happens

	u.handler = vgui.NewHandler(boundRemote{srv: c.srv, id: info.ClientID}, gui, c.logger, vgui.WithExternalEvents())

	c.mu.Lock()
	c.users[info.ClientID] = u
	c.mu.Unlock()

	u.handler.Start() // announces the focused element

	// Greeting and unread messages come last so they are what the user hears.
	greeting := fmt.Sprintf("Welcome, %s. Visit %d.", nick, u.visits)
	if len(u.pending) > 0 {
		greeting += fmt.Sprintf(" %d message(s) while you were away.", len(u.pending))
		c.srv.CancelSpeechTo(u.id)
		c.srv.SendSpeechTo(u.id, greeting)
		for i, m := range lastN(u.pending, unreadSpeech) {
			c.srv.SendSpeechTo(u.id, fmt.Sprintf("%d. %s", i+1, m.line()))
		}
		u.history = append(u.history, u.pending...)
	u.list.Items = historyLines(u.history)
	u.pending = nil
	} else {
		c.srv.CancelSpeechTo(u.id)
		c.srv.SendSpeechTo(u.id, greeting)
	}

	c.persist(u)
	c.logger.Info("User joined", "nick", nick, "id", u.id, "visits", u.visits)
}

func (c *chat) onLeave(clientID int) {
	c.mu.Lock()
	u := c.users[clientID]
	delete(c.users, clientID)
	c.mu.Unlock()
	if u == nil {
		return
	}
	c.persist(u)
	c.logger.Info("User left", "nick", u.nick, "id", clientID)
}

func (c *chat) onPacket(clientID int, packet nvda.Packet) {
	c.mu.Lock()
	u := c.users[clientID]
	c.mu.Unlock()
	if u == nil {
		return
	}
	u.handler.HandlePacket(packet)
}

// send delivers the text in the user's box to everybody else and stores it.
func (c *chat) send(u *user) string {
	text := strings.TrimSpace(u.box.Text)
	if text == "" {
		return "Nothing to send"
	}

	msg := ChatMessage{From: u.nick, Text: text, Time: time.Now()}
	u.box.Text = ""
	u.box.CursorPos = 0
	u.history = append(u.history, msg)
	u.list.Items = historyLines(u.history)
	u.list.SelectedIndex = len(u.list.Items) - 1
	c.persist(u)

	c.mu.Lock()
	recipients := make([]*user, 0, len(c.users))
	for id, other := range c.users {
		if id == u.id {
			continue
		}
		recipients = append(recipients, other)
	}
	c.mu.Unlock()

	for _, r := range recipients {
		c.srv.SendSpeechTo(r.id, msg.line())
		r.history = append(r.history, msg)
		r.list.Items = historyLines(r.history)
		c.persist(r)
	}

	// Everybody who has a session but is offline gets the message queued, so it
	// is replayed the next time they connect.
	if store := c.srv.Sessions(); store != nil {
		for _, nick := range store.Keys() {
			if nick == u.nick {
				continue
			}
			if len(c.srv.ClientsInChannel(nick)) > 0 {
				continue // уже получил живьём выше
			}
			sess := store.Session(nick)
			var pending []ChatMessage
			_ = sess.Get("pending", &pending)
			pending = append(pending, msg)
			_ = sess.Set("pending", lastN(pending, historyLimit))
			if err := sess.Save(); err != nil {
				c.logger.Warn("Could not queue message", "nick", nick, "error", err)
			}
		}
	}

	c.logger.Info("Message sent", "from", u.nick, "to", len(recipients))
	return "Sent"
}

func (c *chat) persist(u *user) {
	if u.session == nil {
		return
	}
	_ = u.session.Set("history", lastN(u.history, historyLimit))
	_ = u.session.Set("pending", u.pending)
	_ = u.session.Set("visits", u.visits)
	_ = u.session.Set("last_seen", time.Now())
	if err := u.session.Save(); err != nil {
		c.logger.Warn("Could not save session", "nick", u.nick, "error", err)
	}
}

func historyLines(msgs []ChatMessage) []string {
	lines := make([]string, 0, len(msgs))
	for _, m := range lastN(msgs, 50) {
		lines = append(lines, m.line())
	}
	if len(lines) == 0 {
		lines = append(lines, "(no messages yet)")
	}
	return lines
}

func lastN(msgs []ChatMessage, n int) []ChatMessage {
	if len(msgs) <= n {
		return msgs
	}
	return msgs[len(msgs)-n:]
}
