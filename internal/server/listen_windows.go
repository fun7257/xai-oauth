package server

import (
	"fmt"
	"os"
)

// ensurePrivateDir validates the socket parent directory on Windows.
//
// POSIX modes are meaningless here (os.Chmod only toggles read-only), so
// per-user isolation relies on NTFS ACLs. The default socket path lives under
// %LOCALAPPDATA% (os.UserCacheDir), whose inherited ACLs grant access to the
// owning user, SYSTEM, and Administrators only — the same trust boundary as
// root on Unix. Operators pointing --socket / XAI_OAUTH_SOCKET at a shared,
// world-readable directory weaken that isolation; the local secret remains
// the second control either way (see SECURITY.md).
func ensurePrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket dir: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket parent must not be a symlink: %s", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("socket parent is not a directory: %s", dir)
	}
	return nil
}

// restrictSocketFile is a no-op on Windows: chmod cannot restrict access;
// the socket file inherits the parent directory's ACLs.
func restrictSocketFile(string) error { return nil }

// removableSocketFile reports whether an existing file at the socket path
// may be a socket. AF_UNIX socket files on Windows are NTFS reparse points;
// depending on the Go version they surface as ModeSocket or ModeIrregular.
// Regular files, directories, and symlinks are never treated as stale sockets.
func removableSocketFile(fi os.FileInfo) bool {
	return fi.Mode()&(os.ModeSocket|os.ModeIrregular) != 0
}
