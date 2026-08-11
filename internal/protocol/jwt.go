package protocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// JWTExp returns the exp claim unix seconds, or 0 if not parseable.
func JWTExp(accessToken string) int64 {
	if accessToken == "" || !strings.Contains(accessToken, ".") {
		return 0
	}
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(padB64(parts[1]))
		if err != nil {
			return 0
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}
	return claims.Exp
}

func padB64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// ExpiresAtFromToken builds expiry from expires_in and/or JWT exp.
// ok is false when neither source yields a time (caller must refresh every time).
func ExpiresAtFromToken(accessToken string, expiresIn int, receivedAt time.Time) (exp time.Time, ok bool) {
	if expiresIn > 0 {
		return receivedAt.Add(time.Duration(expiresIn) * time.Second), true
	}
	if unix := JWTExp(accessToken); unix > 0 {
		return time.Unix(unix, 0), true
	}
	return time.Time{}, false
}
