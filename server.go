// This file adds a server mode to the library.
//
// Normally an NVDA Remote session needs three parties: a master client, a relay
// server and a slave client. The relay only forwards traffic between the two
// clients, which adds a hop (and latency) to every keystroke and every speech
// message.
//
// In server mode this package speaks the relay side of the protocol itself, so
// a master client (NVDA with the Remote addon) connects straight to your app.
// Your app plays the role of the controled (slave) computer: keystrokes arrive
// here directly and speech/beeps go straight back, without a relay in between.
package nvda_remote_go

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	connTypeSlave  string = "slave"
	connTypeMaster string = "master"

	// serverSelfID is the id we present to masters. A relay assigns ids to its
	// clients; in server mode we are the only "client" of our own relay, so we
	// always report ourselves as slave #1.
	serverSelfID = 1

	serverPingInterval = 60 * time.Second
	serverWriteTimeout = 10 * time.Second
	maxLineSize        = 4 << 20 // 4 MiB, speech sequences can be long
)

// NVDARemoteServer is a self contained NVDA Remote server: masters connect to
// it directly, and the library user acts as the controled (slave) machine.
type NVDARemoteServer struct {
	*packetSender

	ln        net.Listener
	channel   string
	logger    *slog.Logger
	eventChan chan Packet
	errorChan chan error
	closeChan chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	eventHandler func(Packet)
	onJoin       func(JoinInfo)
	onLeave      func(clientID int)
	onPacket     func(clientID int, p Packet)
	sessions     *SessionStore

	mu     sync.Mutex
	conns  map[int]*serverConn
	nextID int
	closed bool
}

type serverConn struct {
	conn     net.Conn
	id       int
	connType string
	channel  string
	session  *Session
	joined   bool
	wmu      sync.Mutex
}

// JoinInfo describes a client that joined the channel.
type JoinInfo struct {
	ClientID       int
	Channel        string
	ConnectionType string
	// Session is nil unless the server was started with a SessionStore.
	Session *Session
}

// ServerOptions configures NewServerWithOptions.
type ServerOptions struct {
	Host     string
	Port     string
	Channel  string
	Logger   *slog.Logger
	TLSConfig *tls.Config
	// CertFile/KeyFile keep the TLS identity stable between restarts. When
	// empty, the default location is used.
	CertFile string
	KeyFile  string
	// Sessions enables per-channel persistent context. Nil disables it.
	Sessions *SessionStore
}

// NewServer starts listening and returns a server acting as the slave side.
// host may be empty (all interfaces). channel is the channel name ("key") the
// master has to use; pass an empty channel to accept any of them.
func NewServer(host, port, channel string, lgr *slog.Logger) (*NVDARemoteServer, error) {
	if port == "" {
		port = DEFAULT_PORT
	}
	if lgr == nil {
		lgr = slog.Default()
	}

	return NewServerWithOptions(ServerOptions{Host: host, Port: port, Channel: channel, Logger: lgr})
}

// DefaultCertFiles returns the paths where the server keeps its TLS identity:
// a certificate and key generated once and reused on every start, so the
// server does not look like a brand new machine each time it is launched.
func DefaultCertFiles() (certFile, keyFile string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("config dir: %w", err)
	}
	base := filepath.Join(dir, "nvda_remote_go")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", "", fmt.Errorf("create %s: %w", base, err)
	}
	return filepath.Join(base, "server.crt"), filepath.Join(base, "server.key"), nil
}

// NewServerWithCertFiles is like NewServer but reads the certificate from the
// given files, generating and saving them on first use. A stable certificate
// keeps the server identity constant between restarts.
func NewServerWithCertFiles(host, port, channel, certFile, keyFile string, lgr *slog.Logger) (*NVDARemoteServer, error) {
	return NewServerWithOptions(ServerOptions{
		Host: host, Port: port, Channel: channel, Logger: lgr,
		CertFile: certFile, KeyFile: keyFile,
	})
}

// loadOrCreateCert reuses an existing certificate or writes a fresh one.
func loadOrCreateCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err == nil {
					return cert, nil
				}
				// A broken pair is regenerated below instead of blocking startup.
				fmt.Fprintf(os.Stderr, "nvda_remote_go: ignoring unreadable certificate: %v\n", err)
			}
		}
	}

	cert, certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	if certFile != "" && keyFile != "" {
		if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
			return tls.Certificate{}, fmt.Errorf("write %s: %w", certFile, err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, fmt.Errorf("write %s: %w", keyFile, err)
		}
	}
	return cert, nil
}

// NewServerWithOptions starts a server with full control over certificates and
// per-channel sessions.
func NewServerWithOptions(opts ServerOptions) (*NVDARemoteServer, error) {
	port := opts.Port
	if port == "" {
		port = DEFAULT_PORT
	}
	lgr := opts.Logger
	if lgr == nil {
		lgr = slog.Default()
	}

	cfg := opts.TLSConfig
	if cfg == nil || len(cfg.Certificates) == 0 {
		certFile, keyFile := opts.CertFile, opts.KeyFile
		if certFile == "" || keyFile == "" {
			var err error
			certFile, keyFile, err = DefaultCertFiles()
			if err != nil {
				return nil, err
			}
		}
		cert, err := loadOrCreateCert(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	addr := net.JoinHostPort(opts.Host, port)
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}

	s := &NVDARemoteServer{
		ln:        ln,
		channel:   opts.Channel,
		logger:    lgr,
		eventChan: make(chan Packet, 1000),
		errorChan: make(chan error, 10),
		closeChan: make(chan struct{}),
		conns:     make(map[int]*serverConn),
		nextID:    2,
		sessions:  opts.Sessions,
	}
	s.packetSender = newPacketSender(s.Send, lgr)

	s.wg.Add(2)
	go s.acceptLoop()
	go s.pingLoop()

	lgr.Info("NVDA remote server listening", "address", ln.Addr().String(), "channel", opts.Channel,
		"sessions", opts.Sessions != nil)
	return s, nil
}

// NewServerWithTLSConfig is like NewServer but lets you supply your own TLS
// configuration (e.g. a real certificate instead of the generated one).
func NewServerWithTLSConfig(host, port, channel string, cfg *tls.Config, lgr *slog.Logger) (*NVDARemoteServer, error) {
	if port == "" {
		port = DEFAULT_PORT
	}
	if lgr == nil {
		lgr = slog.Default()
	}
	if cfg == nil || len(cfg.Certificates) == 0 {
		return nil, fmt.Errorf("TLS config without certificates")
	}

	addr := net.JoinHostPort(host, port)
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}

	s := &NVDARemoteServer{
		ln:        ln,
		channel:   channel,
		logger:    lgr,
		eventChan: make(chan Packet, 1000),
		errorChan: make(chan error, 10),
		closeChan: make(chan struct{}),
		conns:     make(map[int]*serverConn),
		nextID:    2, // 1 is reserved for ourselves
	}
	s.packetSender = newPacketSender(s.Send, lgr)

	s.wg.Add(2)
	go s.acceptLoop()
	go s.pingLoop()

	lgr.Info("NVDA remote server listening", "address", ln.Addr().String(), "channel", channel)
	return s, nil
}

// Addr returns the address the server is listening on.
func (s *NVDARemoteServer) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *NVDARemoteServer) acceptLoop() {
	defer s.wg.Done()
	defer s.signalClose()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closeChan:
				return
			default:
				s.sendError(err)
				return
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *NVDARemoteServer) pingLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(serverPingInterval)
	defer ticker.Stop()
	ping := []byte(`{"type":"ping"}`)
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			s.broadcastRaw(ping)
		}
	}
}

func (s *NVDARemoteServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	sc := &serverConn{conn: conn}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	defer func() {
		if sc.joined {
			s.removeConn(sc)
		}
	}()

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var base BasePacket
		if err := json.Unmarshal(line, &base); err != nil {
			s.logger.Debug("Invalid JSON from client", "error", err)
			continue
		}

		switch base.PacketType {
		case "ping":
			// keepalive from the master, never forwarded
			continue

		case "protocol_version":
			var hs HandShakePacket
			if err := json.Unmarshal(line, &hs); err == nil {
				s.logger.Debug("Client handshake", "version", hs.ProtocolVersion)
			}
			continue

		case "join":
			var join SelfJoinPacket
			if err := json.Unmarshal(line, &join); err != nil {
				sc.send([]byte(`{"type":"error","error":"invalid_parameters"}`))
				continue
			}
			if err := s.addConn(sc, join); err != nil {
				sc.send([]byte(`{"type":"error","error":"invalid_parameters"}`))
				s.logger.Warn("Rejected client", "error", err, "channel", join.Channel)
				return
			}
			continue
		}

		if !sc.joined {
			sc.send([]byte(`{"type":"error","error":"invalid_parameters"}`))
			return
		}

		event, err := ParsePacket(line)
		if err != nil {
			s.logger.Debug("Unknown packet", "type", base.PacketType)
			continue
		}
		event = addOrigin(event, sc.id)
		if s.onPacket != nil {
			s.onPacket(sc.id, event)
			continue
		}
		s.deliver(event)
	}

	if err := scanner.Err(); err != nil {
		s.logger.Debug("Connection read error", "error", err)
	}
}

// addConn registers the client, answers the join and notifies the others.
func (s *NVDARemoteServer) addConn(sc *serverConn, join SelfJoinPacket) error {
	if s.channel != "" && join.Channel != s.channel {
		return fmt.Errorf("channel %q does not match %q", join.Channel, s.channel)
	}
	if join.ConnectionType == "" {
		join.ConnectionType = connTypeMaster
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server is closed")
	}
	sc.id = s.nextID
	s.nextID++
	sc.connType = join.ConnectionType
	sc.channel = join.Channel
	if sc.channel == "" {
		sc.channel = s.channel
	}
	if s.sessions != nil {
		sc.session = s.sessions.Session(sc.channel)
	}
	sc.joined = true
	s.conns[sc.id] = sc

	others := make([]NVRClient, 0, len(s.conns))
	userIDs := make([]int, 0, len(s.conns))
	for id := range s.conns {
		if id == sc.id {
			continue
		}
		userIDs = append(userIDs, id)
		others = append(others, NVRClient{ID: id, ConnectionType: s.conns[id].connType})
	}
	s.mu.Unlock()

	// Tell the others that somebody joined.
	if len(others) > 0 {
		joined, _ := json.Marshal(ClientJoinedPacket{
			BasePacket:     BasePacket{PacketType: "client_joined"},
			ID:             sc.id,
			ConnectionType: sc.connType,
		})
		s.broadcastRawExcept(joined, sc.id)
	}

	// The joining client sees us (the slave) plus everyone else.
	clients := []NVRClient{{ID: serverSelfID, ConnectionType: connTypeSlave}}
	clients = append(clients, others...)
	userIDs = append([]int{serverSelfID}, userIDs...)

	channel := join.Channel
	if channel == "" {
		channel = s.channel
	}
	resp, err := json.Marshal(ChannelJoinedPacket{
		BasePacket: BasePacket{PacketType: "channel_joined"},
		Channel:    channel,
		ID:         sc.id,
		UserIDs:    userIDs,
		Clients:    clients,
	})
	if err != nil {
		return err
	}
	sc.send(resp)
	if s.onJoin != nil {
		s.onJoin(JoinInfo{ClientID: sc.id, Channel: sc.channel, ConnectionType: sc.connType, Session: sc.session})
	}
	s.logger.Info("Client joined", "id", sc.id, "type", sc.connType, "channel", channel)
	return nil
}

func (s *NVDARemoteServer) removeConn(sc *serverConn) {
	s.mu.Lock()
	delete(s.conns, sc.id)
	s.mu.Unlock()

	if sc.session != nil {
		if err := sc.session.Save(); err != nil {
			s.logger.Warn("Could not save session", "channel", sc.channel, "error", err)
		}
	}
	if s.onLeave != nil {
		s.onLeave(sc.id)
	}

	left, _ := json.Marshal(ClientLeftPacket{
		BasePacket: BasePacket{PacketType: "client_left"},
		ID:         sc.id,
	})
	s.broadcastRawExcept(left, sc.id)
	s.logger.Info("Client left", "id", sc.id)
}

func (s *NVDARemoteServer) deliver(event Packet) {
	if s.eventHandler != nil {
		s.eventHandler(event)
		return
	}
	select {
	case s.eventChan <- event:
	case <-s.closeChan:
	}
}

// SetJoinHandler is called whenever a master joins a channel.
func (s *NVDARemoteServer) SetJoinHandler(fn func(JoinInfo)) { s.onJoin = fn }

// SetLeaveHandler is called when a connected client disconnects.
func (s *NVDARemoteServer) SetLeaveHandler(fn func(clientID int)) { s.onLeave = fn }

// SetPacketHandler delivers packets per client instead of to the shared
// Events() channel. Use it when every user needs their own state, e.g. one
// GUI per connected master.
func (s *NVDARemoteServer) SetPacketHandler(fn func(clientID int, p Packet)) { s.onPacket = fn }

// Sessions returns the session store, or nil when sessions are disabled.
func (s *NVDARemoteServer) Sessions() *SessionStore { return s.sessions }

// ChannelByClientID tells which channel a connected client belongs to.
func (s *NVDARemoteServer) ChannelByClientID(id int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.conns[id]
	if !ok || !sc.joined {
		return "", false
	}
	return sc.channel, true
}

// ClientsInChannel lists client ids currently joined to a channel.
func (s *NVDARemoteServer) ClientsInChannel(channel string) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]int, 0, len(s.conns))
	for id, sc := range s.conns {
		if sc.joined && sc.channel == channel {
			ids = append(ids, id)
		}
	}
	return ids
}

// SendToClient sends a packet to one connected master.
func (s *NVDARemoteServer) SendToClient(id int, p Packet) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.sendRawToClient(id, injectOrigin(data, serverSelfID))
}

// sendRawToClient writes already encoded JSON to a single connection.
func (s *NVDARemoteServer) sendRawToClient(id int, data []byte) error {
	s.mu.Lock()
	sc := s.conns[id]
	s.mu.Unlock()
	if sc == nil || !sc.joined {
		return fmt.Errorf("client %d is not connected", id)
	}
	sc.send(data)
	return nil
}

// SendToChannel sends a packet to every client joined to one channel.
func (s *NVDARemoteServer) SendToChannel(channel string, p Packet) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	data = injectOrigin(data, serverSelfID)
	for _, id := range s.ClientsInChannel(channel) {
		_ = s.sendRawToClient(id, data)
	}
	return nil
}

// SendSpeechTo speaks a text on one particular client.
func (s *NVDARemoteServer) SendSpeechTo(id int, text string, priority ...int) {
	p := 0
	if len(priority) > 0 {
		p = priority[0]
	}
	_ = s.SendToClient(id, NewSpeakPacket([]interface{}{text}, p))
}

// CancelSpeechTo interrupts speech on one particular client.
func (s *NVDARemoteServer) CancelSpeechTo(id int) {
	_ = s.SendToClient(id, NewCancelSpeechPacket())
}

// SendBeepTo plays a tone on one particular client.
func (s *NVDARemoteServer) SendBeepTo(id int, hz float64, length int, volumes ...int) {
	left, right := 50, 50
	if len(volumes) > 0 {
		left = volumes[0]
	}
	if len(volumes) > 1 {
		right = volumes[1]
	}
	_ = s.SendToClient(id, NewBeepPacket(hz, length, left, right))
}

// Send sends a packet to every connected master, stamped with our slave id so

// the addon knows it is not its own echo.
func (s *NVDARemoteServer) Send(p Packet) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	data = injectOrigin(data, serverSelfID)
	s.broadcastRaw(data)
	return nil
}

func (s *NVDARemoteServer) broadcastRaw(data []byte) {
	s.broadcastRawExcept(data, 0)
}

func (s *NVDARemoteServer) broadcastRawExcept(data []byte, skipID int) {
	s.mu.Lock()
	conns := make([]*serverConn, 0, len(s.conns))
	for id, sc := range s.conns {
		if id == skipID || !sc.joined {
			continue
		}
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	for _, sc := range conns {
		sc.send(data)
	}
}

// send writes one JSON line to this connection, serialised with other writes.
func (sc *serverConn) send(data []byte) {
	sc.wmu.Lock()
	defer sc.wmu.Unlock()
	_ = sc.conn.SetWriteDeadline(time.Now().Add(serverWriteTimeout))
	_, _ = sc.conn.Write(append(data, '\n'))
}

// SetEventHandler routes incoming packets to a callback instead of the channel.
func (s *NVDARemoteServer) SetEventHandler(handler func(Packet)) {
	s.eventHandler = handler
}

// Events returns the channel with packets received from masters.
func (s *NVDARemoteServer) Events() <-chan Packet { return s.eventChan }

// Errors returns non fatal connection errors.
func (s *NVDARemoteServer) Errors() <-chan error { return s.errorChan }

// Close stops the listener and drops every connection.
func (s *NVDARemoteServer) Close() {
	s.logger.Debug("Closing NVDA remote server")
	s.mu.Lock()
	s.closed = true
	conns := make([]*serverConn, 0, len(s.conns))
	for _, sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	for _, sc := range conns {
		sc.conn.Close()
	}
	if s.ln != nil {
		s.ln.Close()
	}
	s.signalClose()
	s.wg.Wait()
	if s.sessions != nil {
		if err := s.sessions.SaveAll(); err != nil {
			s.logger.Warn("Could not save sessions", "error", err)
		}
	}
}

func (s *NVDARemoteServer) signalClose() {
	s.closeOnce.Do(func() { close(s.closeChan) })
}

func (s *NVDARemoteServer) sendError(err error) {
	select {
	case s.errorChan <- err:
	default:
	}
}

// injectOrigin makes sure a marshalled packet carries "origin": id.
func injectOrigin(data []byte, id int) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return data
	}
	if _, ok := m["origin"]; ok {
		return data
	}
	m["origin"] = id
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return out
}

// addOrigin stamps a received packet with the sender id, the way a relay does.
func addOrigin(p Packet, id int) Packet {
	data, err := json.Marshal(p)
	if err != nil {
		return p
	}
	data = injectOrigin(data, id)
	np, err := ParsePacket(data)
	if err != nil {
		return p
	}
	return np
}

// generateSelfSignedCert creates an in-memory certificate, so the server works
// out of the box. The NVDA Remote addon (like most clients) does not verify
// the certificate chain for self hosted servers.
func generateSelfSignedCert() (tls.Certificate, error) {
	cert, _, _, err := generateSelfSignedCertPEM()
	return cert, err
}

// generateSelfSignedCertPEM returns the parsed certificate together with its
// PEM encoding so it can be persisted.
func generateSelfSignedCertPEM() (tls.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nvda-remote-go server", Organization: []string{"nvda-remote-go"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.IPv4zero},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	return pair, certPEM, keyPEM, nil
}
