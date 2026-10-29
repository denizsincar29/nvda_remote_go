package nvda_remote_go

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// ErrNoValue is returned by Session.Get when the key was never stored.
var ErrNoValue = errors.New("session: no such value")

// Session is a small persisted key/value store attached to one channel (for a
// chat, the channel is the user's nickname). It only exists in server mode: a
// relay never hands state to its clients, but when this process is the server
// it can remember whatever each user left behind.
type Session struct {
	Key  string
	path string

	mu     sync.Mutex
	values map[string]json.RawMessage
	saved  time.Time
}

// Get decodes a stored value into out. Returns ErrNoValue if nothing is stored.
func (s *Session) Get(name string, out any) error {
	s.mu.Lock()
	raw, ok := s.values[name]
	s.mu.Unlock()
	if !ok {
		return ErrNoValue
	}
	return json.Unmarshal(raw, out)
}

// Set stores any JSON-marshalable value. Call Save to write it to disk.
func (s *Session) Set(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.values[name] = raw
	s.mu.Unlock()
	return nil
}

// Delete removes a value.
func (s *Session) Delete(name string) {
	s.mu.Lock()
	delete(s.values, name)
	s.mu.Unlock()
}

// Has reports whether a value is present.
func (s *Session) Has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.values[name]
	return ok
}

// Save writes the session to disk atomically.
func (s *Session) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Session) saveLocked() error {
	payload := struct {
		Key    string                     `json:"key"`
		Saved  time.Time                  `json:"saved"`
		Values map[string]json.RawMessage `json:"values"`
	}{
		Key:    s.Key,
		Saved:  time.Now(),
		Values: s.values,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.saved = time.Now()
	return nil
}

// SessionStore keeps one Session per channel, persisted as JSON files.
type SessionStore struct {
	dir string

	mu       sync.Mutex
	sessions map[string]*Session
}

var sessionFileUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// NewSessionStore creates the directory if needed. An empty dir disables
// persistence and keeps sessions in memory only.
func NewSessionStore(dir string) (*SessionStore, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("session store: %w", err)
		}
	}
	return &SessionStore{dir: dir, sessions: make(map[string]*Session)}, nil
}

// Dir returns the directory sessions are stored in ("" for memory only).
func (st *SessionStore) Dir() string { return st.dir }

// Session returns the session for a channel, creating (and loading) it once.
func (st *SessionStore) Session(key string) *Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.sessions[key]; ok {
		return s
	}
	s := &Session{Key: key, values: make(map[string]json.RawMessage)}
	if st.dir != "" {
		s.path = filepath.Join(st.dir, st.fileName(key))
		s.load()
	}
	st.sessions[key] = s
	return s
}

// Keys lists channels that have a session in memory or on disk.
func (st *SessionStore) Keys() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	seen := make(map[string]struct{}, len(st.sessions))
	for k := range st.sessions {
		seen[k] = struct{}{}
	}
	if st.dir != "" {
		entries, err := os.ReadDir(st.dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
					continue
				}
				if key, ok := readSessionKey(filepath.Join(st.dir, e.Name())); ok {
					seen[key] = struct{}{}
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SaveAll flushes every session that was touched.
func (st *SessionStore) SaveAll() error {
	st.mu.Lock()
	sessions := make([]*Session, 0, len(st.sessions))
	for _, s := range st.sessions {
		sessions = append(sessions, s)
	}
	st.mu.Unlock()

	var firstErr error
	for _, s := range sessions {
		if err := s.Save(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Delete removes a session from memory and disk.
func (st *SessionStore) Delete(key string) error {
	st.mu.Lock()
	s := st.sessions[key]
	delete(st.sessions, key)
	st.mu.Unlock()
	if s != nil && s.path != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (st *SessionStore) fileName(key string) string {
	safe := sessionFileUnsafe.ReplaceAllString(key, "_")
	if len(safe) > 48 {
		safe = safe[:48]
	}
	sum := sha256.Sum256([]byte(key))
	if safe == "" {
		safe = "session"
	}
	return safe + "-" + hex.EncodeToString(sum[:4]) + ".json"
}

func (s *Session) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var payload struct {
		Saved  time.Time                  `json:"saved"`
		Values map[string]json.RawMessage `json:"values"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Values == nil {
		return
	}
	s.mu.Lock()
	s.values = payload.Values
	s.saved = payload.Saved
	s.mu.Unlock()
}

func readSessionKey(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var payload struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Key == "" {
		return "", false
	}
	return payload.Key, true
}
