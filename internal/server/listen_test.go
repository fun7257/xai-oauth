package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// shortTempDir puts the test tree under /tmp with a short prefix when
// available (macOS AF_UNIX sun_path is ~104 bytes; t.TempDir() under
// /var/folders often exceeds that when nested). Falls back to the OS
// default temp dir (e.g. on Windows, where /tmp does not exist).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xo-")
	if err != nil {
		dir, err = os.MkdirTemp("", "xo-")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenUnixRoundTrip(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "s.sock")

	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
		RemoveUnixSocket(sock)
	}()

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

func TestListenUnixRefusesLiveSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "s.sock")

	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
		RemoveUnixSocket(sock)
	}()

	// A second bind on the same path must refuse instead of deleting the
	// live daemon's socket out from under it.
	if _, err := ListenUnix(sock); err == nil {
		t.Fatal("expected refuse while socket is live")
	}

	// The live listener must still be reachable afterwards.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("original socket unusable after refused bind: %v", err)
	}
	_ = conn.Close()
}

func TestListenUnixRemovesStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "s.sock")

	// Simulate a crashed daemon: bind, then close without unlinking the path.
	addr, err := net.ResolveUnixAddr("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}

	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatalf("expected stale socket to be replaced: %v", err)
	}
	_ = ln.Close()
	RemoveUnixSocket(sock)
}

func TestListenUnixRejectsNonSocketFile(t *testing.T) {
	dir := shortTempDir(t)
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
