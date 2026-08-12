package client

import (
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the default daemon socket path on Windows:
// %LOCALAPPDATA%\xai-oauth\daemon.sock (os.UserCacheDir), whose inherited
// NTFS ACLs restrict access to the owning user, SYSTEM, and Administrators.
// Falls back to the user temp directory (also user-scoped on Windows) when
// LOCALAPPDATA is unavailable.
func DefaultSocketPath() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "xai-oauth", "daemon.sock")
	}
	return filepath.Join(os.TempDir(), "xai-oauth", "daemon.sock")
}
