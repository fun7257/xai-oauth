package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestJWTExp(t *testing.T) {
	payload, _ := json.Marshal(map[string]int64{"exp": 1700000000})
	tok := "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	if got := JWTExp(tok); got != 1700000000 {
		t.Fatalf("JWTExp = %d", got)
	}
	if JWTExp("not-a-jwt") != 0 {
		t.Fatal("expected 0 for opaque")
	}
}

func TestExpiresAtFromToken(t *testing.T) {
	now := time.Unix(1000, 0)
	exp, ok := ExpiresAtFromToken("x", 60, now)
	if !ok || !exp.Equal(now.Add(60*time.Second)) {
		t.Fatalf("expires_in: exp=%v ok=%v", exp, ok)
	}
	payload, _ := json.Marshal(map[string]int64{"exp": 2000})
	tok := "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
	exp, ok = ExpiresAtFromToken(tok, 0, now)
	if !ok || exp.Unix() != 2000 {
		t.Fatalf("jwt: exp=%v ok=%v", exp, ok)
	}
	_, ok = ExpiresAtFromToken("opaque", 0, now)
	if ok {
		t.Fatal("expected no expiry")
	}
}
