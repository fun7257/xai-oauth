package session

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

func TestGetAccessTokenFresh(t *testing.T) {
	s := &Session{
		accessToken:  "at",
		refreshToken: "rt",
		expiresAt:    time.Now().Add(time.Hour),
		hasExpiry:    true,
		state:        StateReady,
	}
	tok, err := s.GetAccessToken(context.Background())
	if err != nil || tok != "at" {
		t.Fatalf("got %q err=%v", tok, err)
	}
}

func TestGetAccessTokenReauthSticky(t *testing.T) {
	s := &Session{state: StateReauthRequired, lastError: "gone"}
	_, err := s.GetAccessToken(context.Background())
	if err != protocol.ErrReauthRequired {
		t.Fatalf("err=%v", err)
	}
}

func TestNewFromLogin(t *testing.T) {
	_, err := NewFromLogin(nil, &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  "a",
			RefreshToken: "r",
			ExpiresIn:    60,
		},
		Discovery: protocol.Discovery{TokenEndpoint: "https://auth.x.ai/oauth2/token"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshSingleflight(t *testing.T) {
	var hits atomic.Int32
	s := &Session{
		accessToken:  "old",
		refreshToken: "rt",
		expiresAt:    time.Now().Add(30 * time.Second), // inside 5m skew → refresh
		hasExpiry:    true,
		state:        StateReady,
		client:       http.DefaultClient,
		refresher: func(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*protocol.TokenResponse, error) {
			hits.Add(1)
			time.Sleep(80 * time.Millisecond)
			return &protocol.TokenResponse{
				AccessToken:  "new-at",
				RefreshToken: "new-rt",
				ExpiresIn:    3600,
				TokenType:    "Bearer",
			}, nil
		},
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := s.GetAccessToken(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if tok != "new-at" {
				errs <- errString("want new-at got " + tok)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("refresh hits = %d, want 1", hits.Load())
	}
}

func TestInvalidGrantStickyNoRetry(t *testing.T) {
	var hits atomic.Int32
	s := &Session{
		accessToken:  "old",
		refreshToken: "rt",
		expiresAt:    time.Now().Add(30 * time.Second),
		hasExpiry:    true,
		state:        StateReady,
		refresher: func(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*protocol.TokenResponse, error) {
			hits.Add(1)
			return nil, &protocol.Error{
				Code:       "refresh_failed",
				Message:    "refresh_failed (HTTP 400)",
				HTTPStatus: 400,
				Kind:       "reauth",
			}
		},
	}

	_, err := s.GetAccessToken(context.Background())
	if err != protocol.ErrReauthRequired {
		t.Fatalf("first: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits after first = %d", hits.Load())
	}

	// Sticky: further calls must not hit IdP again.
	for i := 0; i < 5; i++ {
		_, err := s.GetAccessToken(context.Background())
		if err != protocol.ErrReauthRequired {
			t.Fatalf("sticky %d: %v", i, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits after sticky = %d, want 1", hits.Load())
	}
	if s.Status().State != StateReauthRequired {
		t.Fatalf("state = %s", s.Status().State)
	}
	if s.Status().LastError == "" {
		t.Fatal("expected last_error set")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
