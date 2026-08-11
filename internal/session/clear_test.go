package session

import (
	"context"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

func TestClear(t *testing.T) {
	s := &Session{
		accessToken:  "at",
		refreshToken: "rt",
		expiresAt:    time.Now().Add(time.Hour),
		hasExpiry:    true,
		state:        StateReady,
	}
	s.Clear()
	if s.Status().State != StateReauthRequired {
		t.Fatalf("state %s", s.Status().State)
	}
	_, err := s.GetAccessToken(context.Background())
	if err != protocol.ErrReauthRequired {
		t.Fatalf("err %v", err)
	}
}
