package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ListenUnix binds an HTTP-capable listener on a Unix domain socket path
// (AF_UNIX; supported on Linux, macOS, and Windows 10 1803+ / Server 2019+).
// The parent directory is created if missing and hardened per platform
// (Unix: mode 0700 owned by the current UID; Windows: user-profile ACLs —
// see ensurePrivateDir). The socket file access is restricted per platform
// after bind. An existing socket file at path is removed only after probing
// that nothing accepts connections on it (stale daemon); a live listener is
// refused instead of being silently orphaned.
func ListenUnix(path string) (net.Listener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("unix socket path is empty")
	}
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid unix socket path %q", path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}

	if fi, err := os.Lstat(path); err == nil {
		if !removableSocketFile(fi) {
			return nil, fmt.Errorf("socket path exists and is not a socket: %s", path)
		}
		if socketAlive(path) {
			return nil, fmt.Errorf("socket %s is in use by a live process; stop it first (xai-oauth logout)", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := restrictSocketFile(path); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return ln, nil
}

// socketAlive reports whether something currently accepts connections on the
// Unix socket at path. A refused/failed dial means the file is a stale
// leftover from a crashed process and is safe to remove.
func socketAlive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// RemoveUnixSocket best-effort deletes a socket path after shutdown.
func RemoveUnixSocket(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	_ = os.Remove(path)
}
