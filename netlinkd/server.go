package netlinkd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/apex/log"
)

// Message is a single blocklist update received over the socket.
// It carries a target name plus IPv4 and IPv6 address lists.
type Message struct {
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// Config holds the runtime configuration of the daemon.
type Config struct {
	SocketPath string
	SocketMode os.FileMode
	Family     string // inet (mapped to nftables.TableFamily*)
	Table      string // route
	SetPrefix  string // blocked-
	SetPrefix6 string // blocked6-
}

// Applier applies a decoded Message to the nftables sets.
type Applier interface {
	Apply(msg Message) error
}

// respOK and respNOK are the plain-text, newline-terminated responses written
// back to the client after a request has been processed.
var (
	respOK  = []byte("OK\n")
	respNOK = []byte("NOK\n")
)

// writeResponse writes a single plain-text response line back to the client:
// "OK" on success, "NOK" on failure.
func writeResponse(conn net.Conn, ok bool) error {
	if ok {
		_, err := conn.Write(respOK)
		return err
	}
	_, err := conn.Write(respNOK)
	return err
}

// Server listens on a Unix domain socket and dispatches received messages
// to an Applier.
type Server struct {
	cfg     Config
	applier Applier

	listener net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New constructs a Server together with an nftApplier built from the config.
func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		cfg:     cfg,
		applier: newNftApplier(cfg),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start removes any stale socket file, begins listening on the configured Unix
// socket, and launches the accept loop.
func (s *Server) Start() error {
	if err := os.Remove(s.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	l, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return err
	}
	s.listener = l

	mode := s.cfg.SocketMode
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(s.cfg.SocketPath, mode); err != nil {
		_ = l.Close()
		_ = os.Remove(s.cfg.SocketPath)
		return err
	}

	log.WithField("socket", s.cfg.SocketPath).Info("listening on unix socket")

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop cancels the context, closes the listener to unblock Accept, waits for
// all handlers to finish, and removes the socket file.
func (s *Server) Stop() {
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.wg.Wait()

	if err := os.Remove(s.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.WithError(err).WithField("socket", s.cfg.SocketPath).Warn("failed to remove socket file")
	}
}

// acceptLoop accepts connections until the context is cancelled.
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				// Shutting down: expected error from a closed listener.
				return
			default:
				log.WithError(err).Warn("accept error")
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn reads newline-delimited JSON messages from a single connection
// and dispatches each one to the Applier. A disconnected client just ends the
// handler without affecting others.
func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	// Close the connection when the server is shutting down to unblock reads.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-s.ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var msg Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			log.WithError(err).Warn("failed to decode message")
			if werr := writeResponse(conn, false); werr != nil {
				log.WithError(werr).Debug("failed to write response")
				return
			}
			continue
		}

		ok := true
		if err := s.applier.Apply(msg); err != nil {
			log.WithError(err).WithField("name", msg.Name).Warn("failed to apply message")
			ok = false
		}

		if werr := writeResponse(conn, ok); werr != nil {
			log.WithError(werr).Debug("failed to write response")
			return
		}
	}

	if err := scanner.Err(); err != nil {
		select {
		case <-s.ctx.Done():
			// Expected: connection closed during shutdown.
		default:
			log.WithError(err).Debug("connection read ended")
		}
	}
}
