//go:build !unix

package server

import (
	"fmt"
	"os"
)

// ensurePrivateDir enforces mode 0700. UID ownership is not checked on
// non-Unix platforms (cross-compile / Windows builds of the CLI).
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
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("socket dir %s must be mode 0700, got %04o", dir, perm)
	}
	return nil
}
