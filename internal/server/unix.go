package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// ListenUnix binds an HTTP-capable listener on a Unix domain socket path.
// Parent directory is created with 0700 and must be owned by the current user
// (Unix); the socket file is chmod 0600. An existing socket file at path is
// removed first (stale daemon).
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
		if fi.Mode()&os.ModeSocket != 0 {
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("remove stale socket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("socket path exists and is not a socket: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}

// RemoveUnixSocket best-effort deletes a socket path after shutdown.
func RemoveUnixSocket(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	_ = os.Remove(path)
}
