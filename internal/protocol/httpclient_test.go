package protocol

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckIDPRedirectAllowsXAI(t *testing.T) {
	u, err := url.Parse("https://auth.x.ai/oauth2/token")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: u}
	if err := checkIDPRedirect(req, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCheckIDPRedirectRejectsOffHost(t *testing.T) {
	u, err := url.Parse("https://evil.example/steal")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: u}
	if err := checkIDPRedirect(req, []*http.Request{{}}); err == nil {
		t.Fatal("expected reject")
	}
}

func TestCheckIDPRedirectRejectsNotxAI(t *testing.T) {
	u, err := url.Parse("https://evil.notx.ai/oauth2/token")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: u}
	if err := checkIDPRedirect(req, nil); err == nil {
		t.Fatal("expected reject notx.ai")
	}
}
