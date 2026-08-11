package protocol

import (
	"strings"
	"testing"
)

func TestIsXAIHost(t *testing.T) {
	ok := []string{
		"x.ai",
		"X.AI",
		"accounts.x.ai",
		"auth.x.ai",
		"api.x.ai",
		"a.b.x.ai",
		"x.ai.", // trailing dot trimmed
	}
	for _, h := range ok {
		if !isXAIHost(h) {
			t.Fatalf("expected allow %q", h)
		}
	}
	bad := []string{
		"",
		"evil.com",
		"notx.ai",
		"evil.notx.ai",
		"x.ai.evil.com",
		"xx.ai",
		"x.aai",
		".x.ai",
		"x..ai",
		"example.com",
	}
	for _, h := range bad {
		if isXAIHost(h) {
			t.Fatalf("expected reject %q", h)
		}
	}
}

func TestValidateXAIURLRejectsNotxAI(t *testing.T) {
	if err := ValidateXAIURL("https://evil.notx.ai/oauth2/token", "token_endpoint"); err == nil {
		t.Fatal("expected reject evil.notx.ai")
	}
	if err := ValidateXAIURL("https://auth.x.ai/oauth2/token", "token_endpoint"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUserCode(t *testing.T) {
	if err := ValidateUserCode("ABCD-EFGH"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUserCode("bad code"); err == nil {
		t.Fatal("expected reject space")
	}
	if err := ValidateUserCode("x\n"); err == nil {
		t.Fatal("expected reject control")
	}
	if err := ValidateUserCode(strings.Repeat("A", MaxUserCodeLen+1)); err == nil {
		t.Fatal("expected reject oversize")
	}
}

func TestValidateVerificationURI(t *testing.T) {
	if err := ValidateVerificationURI("https://accounts.x.ai/oauth2/device?user_code=AB"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVerificationURI("https://evil.notx.ai/phish"); err == nil {
		t.Fatal("expected reject notx.ai")
	}
	if err := ValidateVerificationURI("https://evil.example/phish"); err == nil {
		t.Fatal("expected reject non-x.ai host")
	}
	if err := ValidateVerificationURI("javascript:alert(1)"); err == nil {
		t.Fatal("expected reject javascript")
	}
	if err := ValidateVerificationURI("http://accounts.x.ai/x"); err == nil {
		t.Fatal("expected reject http")
	}
	if err := ValidateVerificationURI("https://accounts.x.ai/x\x00"); err == nil {
		t.Fatal("expected reject control")
	}
	long := "https://accounts.x.ai/" + strings.Repeat("a", MaxVerificationURILen)
	if err := ValidateVerificationURI(long); err == nil {
		t.Fatal("expected reject oversize URI")
	}
}

func TestSanitizeOAuthErrorCode(t *testing.T) {
	if got := sanitizeOAuthErrorCode("invalid_grant"); got != "invalid_grant" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeOAuthErrorCode("INVALID_GRANT"); got != "invalid_grant" {
		t.Fatalf("got %q", got)
	}
	if sanitizeOAuthErrorCode("a; drop table") != "" {
		t.Fatal("expected reject")
	}
	if sanitizeOAuthErrorCode(strings.Repeat("a", 65)) != "" {
		t.Fatal("expected oversize reject")
	}
}

func TestPublicMessageNoBody(t *testing.T) {
	err := wrapHTTP("refresh_failed", 400, "reauth")
	if got := PublicMessage(err); got != "refresh_failed (HTTP 400)" {
		t.Fatalf("got %q", got)
	}
}
