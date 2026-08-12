//go:build unix

package client

import "testing"

func TestDefaultSocketPath(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	p := DefaultSocketPath()
	if p != "/run/user/1000/xai-oauth/daemon.sock" {
		t.Fatalf("got %q", p)
	}
}
