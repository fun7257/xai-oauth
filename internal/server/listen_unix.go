//go:build unix

package server

import (
	"fmt"
	"os"
	"syscall"
)

// ensurePrivateDir requires dir to be owned by the current UID with mode 0700.
// Refuses to listen under a foreign or world/group-accessible parent (critical
// for last-resort $TMPDIR paths on multi-user hosts).
func ensurePrivateDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod socket dir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("socket parent is not a directory: %s", dir)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket parent must not be a symlink: %s", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("socket dir %s must be mode 0700, got %04o", dir, perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("socket dir ownership check unsupported on this platform")
	}
	uid := os.Getuid()
	if uid < 0 {
		return fmt.Errorf("socket dir ownership check unsupported on this platform")
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("socket dir %s not owned by current user (uid %d)", dir, uid)
	}
	return nil
}

// restrictSocketFile chmods the bound socket file to 0600 (owner only).
func restrictSocketFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	return nil
}

// removableSocketFile reports whether an existing file at the socket path is
// a socket (and thus a candidate for stale removal after a liveness probe).
func removableSocketFile(fi os.FileInfo) bool {
	return fi.Mode()&os.ModeSocket != 0
}
