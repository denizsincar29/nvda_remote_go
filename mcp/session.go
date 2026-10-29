package mcp

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"time"

	nv "github.com/denizsincar29/nvda_remote_go"
)

// Utterance — одна фраза, произнесённая NVDA на удалённой машине.
type Utterance struct {
	At   time.Time
	Text string
}

// Session держит одно подключение к релею NVDA Remote и копит речь.
//
// Модель работы: инструменты MCP вызываются по одному, но фоновые
// горутины (чтение событий, ожидание речи) живут всё время сессии,
// поэтому все поля защищены мьютексом.
type Session struct {
	mu sync.Mutex

	client  *nv.NVDARemoteClient
	channel string
	host    string
	port    string

	speech   []Utterance
	clients  []string
	notifyCh chan struct{}
	connAt   time.Time
}

// NewSession создаёт пустую сессию без подключения.
func NewSession() *Session {
	return &Session{notifyCh: make(chan struct{}, 1)}
}

// Connect подключается к релею как master и ждёт первые события канала.
func (s *Session) Connect(host, port, channel string) (string, error) {
	if strings.TrimSpace(host) == "" {
		return "", errors.New("host обязателен")
	}
	if strings.TrimSpace(channel) == "" {
		return "", errors.New("channel (ключ) обязателен")
	}
	if port == "" {
		port = nv.DEFAULT_PORT
	}

	s.Disconnect()

	lgr := slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	c, err := nv.NewClient(host, port, channel, "master", lgr)
	if err != nil {
		return "", fmt.Errorf("подключение к %s:%s: %w", host, port, err)
	}

	s.mu.Lock()
	s.client = c
	s.channel = channel
	s.host = host
	s.port = port
	s.speech = nil
	s.clients = nil
	s.connAt = time.Now()
	s.mu.Unlock()

	go s.readEvents(c)

	// Ждём channel_joined: без него непонятно, принял ли релей ключ.
	_ = s.WaitForSpeech(1500 * time.Millisecond)

	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("подключено к %s:%s, канал %q, клиенты: %v", host, port, channel, s.clients), nil
}

// Disconnect закрывает соединение, если оно есть.
func (s *Session) Disconnect() {
	s.mu.Lock()
	c := s.client
	s.client = nil
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// Connected сообщает, есть ли активное подключение.
func (s *Session) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client != nil
}

func (s *Session) readEvents(c *nv.NVDARemoteClient) {
	for ev := range c.Events() {
		switch e := ev.(type) {
		case nv.SpeakPacket:
			var b strings.Builder
			for _, item := range e.Sequence {
				if str, ok := item.(string); ok {
					b.WriteString(str)
				}
			}
			if text := strings.TrimSpace(b.String()); text != "" {
				s.pushSpeech(text)
			}
		case nv.ChannelJoinedPacket:
			s.setClients(e.Clients)
		case nv.ClientJoinedPacket:
			s.appendClient(fmt.Sprintf("%d (%s)", e.ID, e.ConnectionType))
		case nv.ClientLeftPacket:
			s.removeClient(e.ID)
		}
	}
}

func (s *Session) pushSpeech(text string) {
	s.mu.Lock()
	s.speech = append(s.speech, Utterance{At: time.Now(), Text: text})
	if len(s.speech) > 500 {
		s.speech = s.speech[len(s.speech)-500:]
	}
	s.mu.Unlock()
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

func (s *Session) setClients(clients []nv.NVRClient) {
	s.mu.Lock()
	s.clients = s.clients[:0]
	for _, c := range clients {
		s.clients = append(s.clients, fmt.Sprintf("%d (%s)", c.ID, c.ConnectionType))
	}
	s.mu.Unlock()
}

func (s *Session) appendClient(desc string) {
	s.mu.Lock()
	for _, existing := range s.clients {
		if existing == desc {
			s.mu.Unlock()
			return
		}
	}
	s.clients = append(s.clients, desc)
	s.mu.Unlock()
}

func (s *Session) removeClient(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := fmt.Sprintf("%d (", id)
	out := s.clients[:0]
	for _, c := range s.clients {
		if !strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	s.clients = out
}

// Clients возвращает список клиентов канала.
func (s *Session) Clients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.clients...)
}

// SpeechSince возвращает всю речь, произнесённую после момента t.
func (s *Session) SpeechSince(t time.Time) []Utterance {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Utterance
	for _, u := range s.speech {
		if u.At.After(t) {
			out = append(out, u)
		}
	}
	return out
}

// DrainSpeech отдаёт и очищает накопленную речь.
func (s *Session) DrainSpeech() []Utterance {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Utterance(nil), s.speech...)
	s.speech = nil
	return out
}

// WaitForSpeech ждёт новую речь (или таймаут) и возвращает всё, что
// успело накопиться. Используется как «подожди и послушай».
func (s *Session) WaitForSpeech(timeout time.Duration) []Utterance {
	deadline := time.Now().Add(timeout)
	s.mu.Lock()
	before := len(s.speech)
	s.mu.Unlock()

	for time.Now().Before(deadline) {
		s.mu.Lock()
		after := len(s.speech)
		s.mu.Unlock()
		if after > before {
			// даём NVDA договорить: речь приходит несколькими пакетами
			time.Sleep(350 * time.Millisecond)
			s.mu.Lock()
			out := append([]Utterance(nil), s.speech[before:]...)
			s.mu.Unlock()
			return out
		}
		select {
		case <-s.notifyCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

// SendKeys отправляет последовательность аккордов с паузой и разбросом.
//
// Разброс (jitter) нужен не для «обхода защит» как самоцели, а чтобы
// поток клавиш не выглядел идеально машинным: одинаковые интервалы
// ломают некоторые игры и формы. delay — базовая пауза.
func (s *Session) SendKeys(keys []string, pause time.Duration, jitter float64) error {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return errors.New("нет подключения: сначала вызовите connect")
	}
	for i, k := range keys {
		c.SendKeystroke(strings.TrimSpace(k))
		if i == len(keys)-1 {
			break
		}
		time.Sleep(jittered(pause, jitter))
	}
	return nil
}

// TypeText набирает текст посимвольно с человеческим ритмом.
func (s *Session) TypeText(text string, keysPerSec float64, jitter float64) error {
	keys, err := KeystrokesForText(text)
	if err != nil {
		return err
	}
	if keysPerSec <= 0 {
		keysPerSec = 5
	}
	base := time.Duration(float64(time.Second) / keysPerSec)
	return s.SendKeys(keys, base, jitter)
}

// KeyDown/KeyUp нужны для удержаний вроде «зажать alt и жать tab».
func (s *Session) KeyDown(key string) error {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return errors.New("нет подключения: сначала вызовите connect")
	}
	c.SendKey(key, true)
	return nil
}

// KeyUp отпускает клавишу.
func (s *Session) KeyUp(key string) error {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return errors.New("нет подключения: сначала вызовите connect")
	}
	c.SendKey(key, false)
	return nil
}

// Speak отправляет речь на удалённую машину (озвучить что-то).
func (s *Session) Speak(text string) error {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return errors.New("нет подключения: сначала вызовите connect")
	}
	c.SendSpeech(text)
	return nil
}

// WindowList перечисляет открытые окна, обходя переключатель Alt+Tab.
//
// Механика как у человека: зажимаем Alt, жмём Tab, слушаем, что скажет
// NVDA про новое окно, и так по кругу, пока имя не начнёт повторяться
// (значит, круг замкнулся).
func (s *Session) WindowList(maxWindows int, keyPause time.Duration) ([]string, error) {
	if maxWindows <= 0 {
		maxWindows = 25
	}
	if keyPause <= 0 {
		keyPause = 450 * time.Millisecond
	}
	if err := s.KeyDown("alt"); err != nil {
		return nil, err
	}
	defer func() { _ = s.KeyUp("alt") }()

	seen := make(map[string]bool)
	var windows []string
	emptyRounds := 0

	for i := 0; i < maxWindows; i++ {
		if err := s.KeyDown("tab"); err != nil {
			return windows, err
		}
		_ = s.KeyUp("tab")

		found := s.WaitForSpeech(keyPause)
		if len(found) == 0 {
			emptyRounds++
			if emptyRounds >= 2 {
				break
			}
			continue
		}
		emptyRounds = 0
		name := strings.TrimSpace(found[len(found)-1].Text)
		if name == "" {
			continue
		}
		if seen[name] {
			break
		}
		seen[name] = true
		windows = append(windows, name)
	}
	return windows, nil
}

// jittered возвращает паузу со случайным отклонением ±jitter.
func jittered(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	if jitter > 1 {
		jitter = 1
	}
	factor := 1 + (rand.Float64()*2-1)*jitter
	d := time.Duration(float64(base) * factor)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

// discardWriter глушит вывод логгера клиента: stdout занят протоколом MCP.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
