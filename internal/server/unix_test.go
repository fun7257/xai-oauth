//go:build unix

package server

import (
	"os"
	"path/filepath"
	"testing"
)

// Unix-specific hardening assertions (POSIX modes / ownership). Portable
// listener behavior is covered in listen_test.go.

func TestListenUnixSocketMode0600(t *testing.T) {
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
}

func TestListenUnixTightensParentDir(t *testing.T) {
	// Nested dir starts loose; ListenUnix must chmod to 0700 and still bind.
	parent := shortTempDir(t)
	dir := filepath.Join(parent, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
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
	dir := shortTempDir(t)
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
