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

func TestListenUnixTightensParentDir(t *testing.T) {
	// Nested dir starts loose; ListenUnix must chmod to 0700 and still bind.
	parent := t.TempDir()
	dir := filepath.Join(parent, "xai-oauth")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "daemon.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = ln.Close()
		RemoveUnixSocket(sock)
	}()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("parent perm = %04o want 0700", perm)
	}
}

func TestEnsurePrivateDirRejectsWrongOwner(t *testing.T) {
	// Without root we cannot create a foreign-owned dir; exercise the Stat_t
	// path with a normal private dir and a non-directory path.
	dir := t.TempDir()
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("own temp dir: %v", err)
	}
	file := filepath.Join(dir, "notdir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(file); err == nil {
		t.Fatal("expected reject non-directory")
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
