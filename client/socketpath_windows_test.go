package client

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketPath(t *testing.T) {
	p := DefaultSocketPath()
	want := filepath.Join("xai-oauth", "daemon.sock")
	if !strings.HasSuffix(p, want) {
		t.Fatalf("got %q, want suffix %q", p, want)
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("path %q is not absolute", p)
	}
}
