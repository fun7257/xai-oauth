package session

import (
	"context"
	"net/http"
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

// TestClearDuringRefresh ensures logout wins over an in-flight IdP refresh:
// tokens must not be reinstalled after Clear.
func TestClearDuringRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := &Session{
		accessToken:  "old",
		refreshToken: "rt",
		expiresAt:    time.Now().Add(30 * time.Second), // inside skew → refresh
		hasExpiry:    true,
		state:        StateReady,
		client:       http.DefaultClient,
		refresher: func(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*protocol.TokenResponse, error) {
			close(started)
			<-release
			return &protocol.TokenResponse{
				AccessToken:  "new-at",
				RefreshToken: "new-rt",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			}, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := s.GetAccessToken(context.Background())
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start")
	}
	s.Clear()
	close(release)

	select {
	case err := <-errCh:
		if err != protocol.ErrReauthRequired {
			t.Fatalf("in-flight GetAccessToken: %v, want ErrReauthRequired", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetAccessToken did not return")
	}

	if st := s.Status(); st.State != StateReauthRequired {
		t.Fatalf("state after Clear+refresh = %s, want reauth_required", st.State)
	}
	// Tokens must not have been resurrected: a follow-up Get must stay sticky.
	tok, err := s.GetAccessToken(context.Background())
	if err != protocol.ErrReauthRequired || tok != "" {
		t.Fatalf("after race: tok=%q err=%v", tok, err)
	}
}
