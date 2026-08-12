package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/internal/session"
)

func TestHandleHandoff(t *testing.T) {
	const secret = "s3cret"
	sess := newReadySession(t)
	shutdown := make(chan struct{}, 1)
	h := (&Server{
		Session:  sess,
		Secret:   secret,
		OnLogout: func() { shutdown <- struct{}{} },
	}).Handler()

	post := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/handoff", nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Secret required.
	if rr := post("wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: HTTP %d", rr.Code)
	}

	rr := post(secret)
	if rr.Code != http.StatusOK {
		t.Fatalf("handoff: HTTP %d body %s", rr.Code, rr.Body.String())
	}
	var out struct {
		AccessToken   string `json:"access_token"`
		RefreshToken  string `json:"refresh_token"`
		TokenEndpoint string `json:"token_endpoint"`
		ExpiresAt     string `json:"expires_at"`
		HasExpiry     bool   `json:"has_expiry"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AccessToken != "at" || out.RefreshToken != "rt" ||
		out.TokenEndpoint != "https://auth.x.ai/oauth2/token" || !out.HasExpiry {
		t.Fatalf("payload %+v", out)
	}
	if _, err := time.Parse(time.RFC3339, out.ExpiresAt); err != nil {
		t.Fatalf("expires_at %q: %v", out.ExpiresAt, err)
	}

	// Daemon drained: /token now 503, shutdown hook fired.
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	tr := httptest.NewRecorder()
	h.ServeHTTP(tr, req)
	if tr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/token after handoff: HTTP %d", tr.Code)
	}
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hook not fired")
	}

	// Second handoff conflicts with handed_off state.
	if rr := post(secret); rr.Code != http.StatusConflict {
		t.Fatalf("second handoff: HTTP %d", rr.Code)
	}
}

func TestHandleHandoffNotReady(t *testing.T) {
	const secret = "s"
	sess := newReadySession(t)
	sess.Clear() // sticky reauth_required
	h := (&Server{Session: sess, Secret: secret}).Handler()

	req := httptest.NewRequest(http.MethodPost, "/handoff", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("HTTP %d", rr.Code)
	}
	var out struct {
		Error string `json:"error"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "handoff_unavailable" || out.State != string(session.StateReauthRequired) {
		t.Fatalf("body %+v", out)
	}
}
