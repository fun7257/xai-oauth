//go:build unix

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/session"
)

// Server serves local token HTTP API.
type Server struct {
	Session *session.Session
	Secret  string
	// OnLogout is called after credentials are cleared (e.g. trigger process shutdown).
	// May be nil.
	OnLogout func()
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /token", s.handleToken)
	mux.HandleFunc("POST /logout", s.handleLogout)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	st := s.Session.Status()
	if st.State == session.StateReady {
		writeJSON(w, http.StatusOK, map[string]any{"ready": true})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"ready": false,
		"state": st.State,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkSecret(w, r) {
		return
	}
	st := s.Session.Status()
	body := map[string]any{
		"state":      st.State,
		"has_expiry": st.HasExpiry,
	}
	if st.HasExpiry && !st.ExpiresAt.IsZero() {
		body["expires_at"] = st.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if st.LastError != "" {
		body["last_error"] = st.LastError
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkSecret(w, r) {
		return
	}
	tok, err := s.Session.GetAccessToken(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, protocol.ErrReauthRequired):
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "reauth_required",
				"message": "refresh token rejected; restart xai-oauth serve and sign in",
			})
		case errors.Is(err, protocol.ErrTierDenied):
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "tier_denied",
				"message": "oauth account not entitled for API access",
			})
		case errors.Is(err, protocol.ErrUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":   "unavailable",
				"message": "token refresh temporarily failed",
			})
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":   "unavailable",
				"message": "token refresh temporarily failed",
			})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": tok,
		"token_type":   "Bearer",
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.checkSecret(w, r) {
		return
	}
	s.Session.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logged_out": true})
	if s.OnLogout != nil {
		// Run after response flush path: schedule so WriteHeader completes first.
		go s.OnLogout()
	}
}

func (s *Server) checkSecret(w http.ResponseWriter, r *http.Request) bool {
	got := bearer(r.Header.Get("Authorization"))
	if !secretEqual(got, s.Secret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "invalid local secret",
		})
		return false
	}
	return true
}

func bearer(h string) string {
	h = strings.TrimSpace(h)
	const p = "bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// secretEqual compares secrets in constant time via SHA-256 digests
// so neither secret length nor content is leaked by early returns.
func secretEqual(got, want string) bool {
	gh := sha256.Sum256([]byte(got))
	wh := sha256.Sum256([]byte(want))
	// Empty want must not match any got (including empty).
	empty := sha256.Sum256(nil)
	wantEmpty := subtle.ConstantTimeCompare(wh[:], empty[:])
	match := subtle.ConstantTimeCompare(gh[:], wh[:])
	// match==1 and wantEmpty==0  => true
	return subtle.ConstantTimeEq(int32(match), 1)&subtle.ConstantTimeEq(int32(wantEmpty), 0) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
