//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoginHandoffJSONRoundTrip(t *testing.T) {
	h := &loginHandoff{
		AccessToken:   "at",
		RefreshToken:  "rt",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
		ExpiresIn:     3600,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(h); err != nil {
		t.Fatal(err)
	}
	var got loginHandoff
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "at" || got.RefreshToken != "rt" || got.ExpiresIn != 3600 {
		t.Fatalf("got %+v", got)
	}
	if !strings.HasPrefix(got.TokenEndpoint, "https://auth.x.ai/") {
		t.Fatalf("endpoint %q", got.TokenEndpoint)
	}
}

func TestZeroHandoff(t *testing.T) {
	h := &loginHandoff{AccessToken: "a", RefreshToken: "r", TokenEndpoint: "e", ExpiresIn: 1}
	zeroHandoff(h)
	if h.AccessToken != "" || h.RefreshToken != "" || h.TokenEndpoint != "" || h.ExpiresIn != 0 {
		t.Fatalf("not zeroed: %+v", h)
	}
}
