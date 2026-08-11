package protocol_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

// These tests lock publish-relevant invariants of the shipped tree
// (stdlib-only module, intentional public OAuth client id). They are not a
// substitute for LICENSE/README, which remain release process concerns.

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../internal/protocol/opensource_invariants_test.go → repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestGoModHasNoThirdPartyRequires(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "module github.com/fun7257/xai-oauth") {
		t.Fatalf("unexpected module path in go.mod:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require ") || line == "require (" {
			t.Fatalf("third-party require not allowed without license inventory: %q", line)
		}
	}
}

func TestPublicOAuthClientIDIsDocumentedConstant(t *testing.T) {
	// Intentional public device-code client (not a private secret).
	const want = "b1a00492-073a-47ea-816f-4c329264a828"
	if protocol.ClientID != want {
		t.Fatalf("ClientID = %q want %q", protocol.ClientID, want)
	}
	if !strings.HasPrefix(protocol.Issuer, "https://auth.x.ai") {
		t.Fatalf("Issuer = %q", protocol.Issuer)
	}
}
