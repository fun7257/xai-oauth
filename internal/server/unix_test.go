package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestListenUnixRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")

	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
		RemoveUnixSocket(sock)
	}()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("not a socket: %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o want 0600", fi.Mode().Perm())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Minimal HTTP/1.0 request over the unix connection.
	_, err = conn.Write([]byte("GET /health HTTP/1.0\r\nHost: xai-oauth\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	if !containsOK(string(buf[:n])) {
		t.Fatalf("response %q", string(buf[:n]))
	}
}

func TestListenUnixRejectsNonSocketFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notasock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(path); err == nil {
		t.Fatal("expected reject regular file")
	}
}

func containsOK(s string) bool {
	return len(s) > 0 && (stringContains(s, "200") || stringContains(s, "ok"))
}

func stringContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
