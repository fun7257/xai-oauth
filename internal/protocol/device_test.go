package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPollDeviceTokenPendingCaseInsensitive(t *testing.T) {
	// AUTHORIZATION_PENDING (upper) must continue polling like authorization_pending.
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "AUTHORIZATION_PENDING"})
			return
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	// ValidateXAIURL requires an x.ai host; rewrite the request to the test
	// server while leaving the request URL host pin-checkable.
	ep := "https://auth.x.ai/oauth2/token"
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req2 := req.Clone(req.Context())
			req2.URL.Scheme = "http"
			req2.URL.Host = srv.Listener.Addr().String()
			req2.RequestURI = ""
			return http.DefaultTransport.RoundTrip(req2)
		}),
		Timeout: 5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tr, err := PollDeviceToken(ctx, client, ep, "dc", 60, 1)
	if err != nil {
		t.Fatalf("PollDeviceToken: %v", err)
	}
	if tr.AccessToken != "at" || tr.RefreshToken != "rt" {
		t.Fatalf("tokens: %+v", tr)
	}
	if n < 2 {
		t.Fatalf("polls = %d, want >= 2 (pending then success)", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
