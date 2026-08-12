package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/session"
)

func newReadySession(t *testing.T) *session.Session {
	t.Helper()
	sess, err := session.NewFromLogin(nil, &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rt",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
		Discovery: protocol.Discovery{TokenEndpoint: "https://auth.x.ai/oauth2/token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestHandleReadyAndStatus(t *testing.T) {
	const secret = "s3cret"
	sess := newReadySession(t)
	h := (&Server{Session: sess, Secret: secret}).Handler()

	get := func(path, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	if rr := get("/ready", ""); rr.Code != http.StatusOK {
		t.Fatalf("ready fresh: HTTP %d body %s", rr.Code, rr.Body.String())
	}

	rr := get("/status", secret)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: HTTP %d", rr.Code)
	}
	var st struct {
		State      string `json:"state"`
		TokenValid bool   `json:"token_valid"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != string(session.StateReady) || !st.TokenValid {
		t.Fatalf("status = %+v, want ready with token_valid", st)
	}

	// After logout the session is sticky reauth: /ready must say so.
	sess.Clear()
	rr = get("/ready", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready after clear: HTTP %d", rr.Code)
	}
	var rd struct {
		Ready bool   `json:"ready"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rd); err != nil {
		t.Fatal(err)
	}
	if rd.Ready || rd.State != string(session.StateReauthRequired) {
		t.Fatalf("ready body = %+v", rd)
	}
}
