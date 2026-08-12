//go:build unix

package client

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultSocketPath returns the default daemon socket path:
//  1. $XDG_RUNTIME_DIR/xai-oauth/daemon.sock if XDG_RUNTIME_DIR is set
//  2. ~/.xai-oauth/daemon.sock if home is available
//  3. $TMPDIR/xai-oauth/daemon.sock otherwise (last resort)
func DefaultSocketPath() string {
	if runtime := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); runtime != "" {
		return filepath.Join(runtime, "xai-oauth", "daemon.sock")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "xai-oauth", "daemon.sock")
	}
	return filepath.Join(home, ".xai-oauth", "daemon.sock")
}
