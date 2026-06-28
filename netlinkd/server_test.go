package netlinkd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
)

// fakeApplier records every message passed to Apply and can be configured to
// return an error from Apply.
type fakeApplier struct {
	mu       sync.Mutex
	messages []Message
	err      error
}

func (f *fakeApplier) Apply(msg Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, msg)
	return f.err
}

func (f *fakeApplier) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeApplier) snapshot() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Message, len(f.messages))
	copy(out, f.messages)
	return out
}

// newTestServer builds a Server with a fake applier on a temp-dir socket.
func newTestServer(t *testing.T) (*Server, *fakeApplier) {
	t.Helper()

	dir := t.TempDir()
	sock := filepath.Join(dir, "test.sock")

	fake := &fakeApplier{}
	s := New(Config{SocketPath: sock})
	s.applier = fake

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	return s, fake
}

func dial(t *testing.T, s *Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", s.cfg.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func writeMessages(t *testing.T, conn net.Conn, msgs ...Message) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, m := range msgs {
		if err := enc.Encode(m); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readResponse reads a single newline-delimited response line from the reader
// and returns it trimmed of the trailing newline.
func readResponse(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return line[:len(line)-1]
}

// waitForMessages waits until the fake applier has at least n messages.
func waitForMessages(t *testing.T, fake *fakeApplier, n int) []Message {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := fake.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d messages, got %d", n, len(fake.snapshot()))
	return nil
}

func TestSingleMessageBothLists(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	writeMessages(t, conn, Message{
		Name: "target",
		IPv4: []string{"10.0.0.1", "10.0.0.2"},
		IPv6: []string{"2001:db8::1"},
	})

	got := waitForMessages(t, fake, 1)
	if len(got) != 1 {
		t.Fatalf("expected 1 message, got %d", len(got))
	}
	m := got[0]
	if m.Name != "target" || len(m.IPv4) != 2 || len(m.IPv6) != 1 {
		t.Fatalf("unexpected message: %+v", m)
	}
}

func TestSynchronousAck(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	r := bufio.NewReader(conn)
	writeMessages(t, conn, Message{
		Name: "target",
		IPv4: []string{"10.0.0.1"},
		IPv6: []string{"2001:db8::1"},
	})

	if resp := readResponse(t, r); resp != "OK" {
		t.Fatalf("expected OK, got %q", resp)
	}

	got := fake.snapshot()
	if len(got) != 1 || got[0].Name != "target" {
		t.Fatalf("unexpected messages: %+v", got)
	}
}

func TestMultipleAcksOrdered(t *testing.T) {
	s, _ := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	r := bufio.NewReader(conn)
	writeMessages(t, conn,
		Message{Name: "a", IPv4: []string{"1.1.1.1"}},
		Message{Name: "b", IPv6: []string{"2001:db8::2"}},
		Message{Name: "c", IPv4: []string{"2.2.2.2"}},
	)

	for i := 0; i < 3; i++ {
		if resp := readResponse(t, r); resp != "OK" {
			t.Fatalf("response %d: expected OK, got %q", i, resp)
		}
	}
}

func TestErrorResponseKeepsConnection(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	r := bufio.NewReader(conn)

	// First message fails to apply -> NOK.
	fake.setErr(fmt.Errorf("apply failed"))
	writeMessages(t, conn, Message{Name: "a", IPv4: []string{"1.1.1.1"}})
	if resp := readResponse(t, r); resp != "NOK" {
		t.Fatalf("expected NOK, got %q", resp)
	}

	// Connection must remain usable; next message succeeds -> OK.
	fake.setErr(nil)
	writeMessages(t, conn, Message{Name: "b", IPv4: []string{"2.2.2.2"}})
	if resp := readResponse(t, r); resp != "OK" {
		t.Fatalf("expected OK after recovery, got %q", resp)
	}
}

func TestMalformedJsonResponse(t *testing.T) {
	s, _ := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	r := bufio.NewReader(conn)

	// Malformed JSON line gets NOK; a following valid message gets OK.
	payload := "not-json\n" + `{"name":"ok","ipv4":["4.4.4.4"]}` + "\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if resp := readResponse(t, r); resp != "NOK" {
		t.Fatalf("expected NOK for malformed json, got %q", resp)
	}
	if resp := readResponse(t, r); resp != "OK" {
		t.Fatalf("expected OK for valid message, got %q", resp)
	}
}

func TestMultipleMessagesOneConnection(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	writeMessages(t, conn,
		Message{Name: "a", IPv4: []string{"1.1.1.1"}},
		Message{Name: "b", IPv6: []string{"2001:db8::2"}},
		Message{Name: "c", IPv4: []string{"2.2.2.2"}},
	)

	got := waitForMessages(t, fake, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "b" || got[2].Name != "c" {
		t.Fatalf("messages out of order: %+v", got)
	}
}

func TestConcurrentConnections(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn := dial(t, s)
			defer conn.Close()
			writeMessages(t, conn, Message{Name: "t", IPv4: []string{"3.3.3.3"}})
		}(i)
	}
	wg.Wait()

	got := waitForMessages(t, fake, n)
	if len(got) != n {
		t.Fatalf("expected %d messages, got %d", n, len(got))
	}
}

func TestEmptyAndMalformedLines(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	defer conn.Close()

	// Blank line, malformed JSON line, then a valid message.
	payload := "\n   \nnot-json\n" + `{"name":"ok","ipv4":["4.4.4.4"]}` + "\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := waitForMessages(t, fake, 1)
	if len(got) != 1 || got[0].Name != "ok" {
		t.Fatalf("expected single valid message, got %+v", got)
	}
}

func TestClientConnectsThenDisconnects(t *testing.T) {
	s, fake := newTestServer(t)
	defer s.Stop()

	conn := dial(t, s)
	// Disconnect immediately without sending anything.
	conn.Close()

	// A subsequent valid connection must still work.
	conn2 := dial(t, s)
	defer conn2.Close()
	writeMessages(t, conn2, Message{Name: "x", IPv4: []string{"5.5.5.5"}})

	got := waitForMessages(t, fake, 1)
	if len(got) != 1 || got[0].Name != "x" {
		t.Fatalf("expected message after reconnect, got %+v", got)
	}
}

func TestShutdownRemovesSocket(t *testing.T) {
	s, _ := newTestServer(t)
	sock := s.cfg.SocketPath

	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket file should exist before Stop: %v", err)
	}

	s.Stop()

	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file should be removed after Stop, stat err: %v", err)
	}
}

func TestApplierInvalidNameRejected(t *testing.T) {
	a := newNftApplier(Config{Table: "route", SetPrefix: "blocked-", SetPrefix6: "blocked6-"})
	err := a.Apply(Message{Name: "bad name!", IPv4: []string{"1.2.3.4"}})
	if err == nil {
		t.Fatalf("expected error for invalid name")
	}
}

func TestApplierEmptyListsNoError(t *testing.T) {
	a := newNftApplier(Config{Table: "route", SetPrefix: "blocked-", SetPrefix6: "blocked6-"})
	if err := a.Apply(Message{Name: "target"}); err != nil {
		t.Fatalf("expected no error for empty lists, got %v", err)
	}
}

func TestParseIPv4Elements(t *testing.T) {
	elems := parseIPv4Elements([]string{"10.0.0.1", "bad", "2001:db8::1", "10.0.0.2"})
	if len(elems) != 2 {
		t.Fatalf("expected 2 valid ipv4 elements, got %d", len(elems))
	}
	for _, e := range elems {
		if len(e.Key) != 4 {
			t.Fatalf("expected 4-byte ipv4 key, got %d bytes", len(e.Key))
		}
	}
}

func TestParseIPv6Elements(t *testing.T) {
	elems := parseIPv6Elements([]string{"2001:db8::1", "10.0.0.1", "bad", "::1"})
	if len(elems) != 2 {
		t.Fatalf("expected 2 valid ipv6 elements, got %d", len(elems))
	}
	for _, e := range elems {
		if len(e.Key) != 16 {
			t.Fatalf("expected 16-byte ipv6 key, got %d bytes", len(e.Key))
		}
	}
}

func TestFamilyFromString(t *testing.T) {
	cases := map[string]nftables.TableFamily{
		"inet": nftables.TableFamilyINet,
		"":     nftables.TableFamilyINet,
		"ip":   nftables.TableFamilyIPv4,
		"ip6":  nftables.TableFamilyIPv6,
		"junk": nftables.TableFamilyINet,
	}
	for in, want := range cases {
		if got := familyFromString(in); got != want {
			t.Fatalf("familyFromString(%q) = %v, want %v", in, got, want)
		}
	}
}
