package session

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

func readySession() *Session {
	return &Session{
		accessToken:   "at",
		refreshToken:  "rt",
		tokenEndpoint: "https://auth.x.ai/oauth2/token",
		expiresAt:     time.Now().Add(time.Hour),
		hasExpiry:     true,
		state:         StateReady,
	}
}

func TestHandoffDrains(t *testing.T) {
	s := readySession()
	d, state, err := s.Handoff()
	if err != nil || state != StateHandedOff {
		t.Fatalf("Handoff: state=%s err=%v", state, err)
	}
	if d.AccessToken != "at" || d.RefreshToken != "rt" ||
		d.TokenEndpoint != "https://auth.x.ai/oauth2/token" || !d.HasExpiry {
		t.Fatalf("snapshot %+v", d)
	}

	// Drained: no credentials, unavailable to token callers.
	if s.accessToken != "" || s.refreshToken != "" {
		t.Fatal("credentials not wiped")
	}
	if _, err := s.GetAccessToken(context.Background()); !errors.Is(err, protocol.ErrUnavailable) {
		t.Fatalf("GetAccessToken after handoff: %v", err)
	}
	if st := s.Status(); st.State != StateHandedOff || st.LastError != "handed_off" {
		t.Fatalf("status %+v", st)
	}
	if ready, reason := s.Ready(); ready || reason != string(StateHandedOff) {
		t.Fatalf("ready=%v reason=%q", ready, reason)
	}

	// Second handoff must conflict.
	if _, state, err := s.Handoff(); err == nil || state != StateHandedOff {
		t.Fatalf("second handoff: state=%s err=%v", state, err)
	}
}

func TestHandoffNotReady(t *testing.T) {
	for _, st := range []State{StateReauthRequired, StateTierDenied} {
		s := &Session{state: st}
		if _, got, err := s.Handoff(); err == nil || got != st {
			t.Fatalf("state %s: got=%s err=%v", st, got, err)
		}
	}
}

func TestRestoreHandoff(t *testing.T) {
	s := readySession()
	d, _, err := s.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	s.RestoreHandoff(d)

	if st := s.Status(); st.State != StateReady || st.LastError != "" {
		t.Fatalf("status after restore: %+v", st)
	}
	tok, err := s.GetAccessToken(context.Background())
	if err != nil || tok != "at" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
}

func TestRestoreHandoffDoesNotResurrectAfterClear(t *testing.T) {
	s := readySession()
	d, _, err := s.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	// Logout raced the handoff delivery: restore must be a no-op.
	s.Clear()
	s.RestoreHandoff(d)
	if st := s.Status(); st.State != StateReauthRequired {
		t.Fatalf("state after clear+restore: %s", st.State)
	}
	if _, err := s.GetAccessToken(context.Background()); !errors.Is(err, protocol.ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestHandoffWaitsForInflightRefresh(t *testing.T) {
	// The critical rotation race: a snapshot taken while a refresh is in
	// flight would capture the already-consumed old RT. Handoff must block
	// until the refresh finishes and then snapshot the rotated tokens.
	refreshStarted := make(chan struct{})
	var handoffDuringRefresh atomic.Bool

	s := &Session{
		accessToken:   "old-at",
		refreshToken:  "old-rt",
		tokenEndpoint: "https://auth.x.ai/oauth2/token",
		expiresAt:     time.Now().Add(30 * time.Second), // inside skew → refresh
		hasExpiry:     true,
		state:         StateReady,
		client:        http.DefaultClient,
		refresher: func(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*protocol.TokenResponse, error) {
			close(refreshStarted)
			time.Sleep(150 * time.Millisecond)
			return &protocol.TokenResponse{
				AccessToken:  "new-at",
				RefreshToken: "new-rt",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			}, nil
		},
	}

	tokCh := make(chan string, 1)
	go func() {
		tok, err := s.GetAccessToken(context.Background())
		if err != nil {
			t.Errorf("GetAccessToken: %v", err)
		}
		tokCh <- tok
	}()

	<-refreshStarted
	handoffDuringRefresh.Store(true)
	d, _, err := s.Handoff() // must block until the refresh stored new-rt
	if err != nil {
		t.Fatalf("Handoff: %v", err)
	}
	if d.RefreshToken != "new-rt" || d.AccessToken != "new-at" {
		t.Fatalf("snapshot lost the rotation: %+v", d)
	}
	if tok := <-tokCh; tok != "new-at" {
		t.Fatalf("refresh caller got %q", tok)
	}
	if !handoffDuringRefresh.Load() {
		t.Fatal("test setup: handoff did not overlap refresh")
	}
}
