package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/server"
	"github.com/fun7257/xai-oauth/internal/session"
)

// Session takeover (zero-reauth upgrade): a new serve process asks the
// running daemon for its in-memory session over POST /handoff, then replaces
// it on the socket. The endpoint returns the refresh token, so it is
// deliberately not exposed through the public SDK; this file is the only
// client.

const takeoverHost = "http://xai-oauth.local"

// unixHTTP builds a plain HTTP client over the Unix socket (no SDK: the SDK
// requires the secret env and must not learn a /handoff method).
func unixHTTP(sock string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

// daemonAlive reports whether something answers GET /health on the socket.
func daemonAlive(sock string) bool {
	hc := unixHTTP(sock, 500*time.Millisecond)
	resp, err := hc.Get(takeoverHost + "/health")
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type takeoverOutcome int

const (
	// takeoverAcquired: session received; skip device login.
	takeoverAcquired takeoverOutcome = iota
	// takeoverDeadSession: daemon alive but its session is sticky-dead
	// (reauth_required / tier_denied); log in fresh, then replace it.
	takeoverDeadSession
)

// attemptHandoff asks the running daemon to hand over its session.
// The generous timeout covers an in-flight IdP refresh the daemon must
// finish before draining (bounded by the IdP request timeout).
func attemptHandoff(sock, sec string) (takeoverOutcome, *loginHandoff, error) {
	hc := unixHTTP(sock, protocol.IDPRequestTimeout+10*time.Second)
	req, err := http.NewRequest(http.MethodPost, takeoverHost+"/handoff", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("daemon on %s stopped answering during takeover: %w", sock, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		h, err := parseHandoffResponse(body)
		if err != nil {
			return 0, nil, fmt.Errorf("takeover failed: %w", err)
		}
		return takeoverAcquired, h, nil

	case http.StatusUnauthorized:
		return 0, nil, fmt.Errorf("socket %s is already in use (wrong secret or foreign listener); logout or free the path", sock)

	case http.StatusConflict:
		var p struct {
			State string `json:"state"`
		}
		_ = json.Unmarshal(body, &p)
		switch p.State {
		case string(session.StateReauthRequired), string(session.StateTierDenied):
			return takeoverDeadSession, nil, nil
		default:
			return 0, nil, fmt.Errorf("another takeover is in progress on %s (state %q); check: xai-oauth status", sock, p.State)
		}

	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return 0, nil, fmt.Errorf("daemon on %s predates session takeover (no /handoff); run: xai-oauth logout, then serve again (one-time re-login)", sock)

	default:
		return 0, nil, fmt.Errorf("takeover failed: daemon returned HTTP %d", resp.StatusCode)
	}
}

// parseHandoffResponse validates the handoff payload and converts it into
// the same loginHandoff shape the daemon child already consumes (absolute
// expiry becomes a relative expires_in; sub-second loss is irrelevant next
// to the 5-minute refresh skew).
func parseHandoffResponse(body []byte) (*loginHandoff, error) {
	var p struct {
		AccessToken   string `json:"access_token"`
		RefreshToken  string `json:"refresh_token"`
		TokenEndpoint string `json:"token_endpoint"`
		ExpiresAt     string `json:"expires_at"`
		HasExpiry     bool   `json:"has_expiry"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid handoff JSON")
	}
	if strings.TrimSpace(p.AccessToken) == "" || strings.TrimSpace(p.RefreshToken) == "" {
		return nil, fmt.Errorf("handoff response missing tokens")
	}
	if err := protocol.ValidateXAIURL(p.TokenEndpoint, "token_endpoint"); err != nil {
		return nil, err
	}
	h := &loginHandoff{
		AccessToken:   p.AccessToken,
		RefreshToken:  p.RefreshToken,
		TokenEndpoint: p.TokenEndpoint,
	}
	if p.HasExpiry && p.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil {
			if secs := int(time.Until(t).Seconds()); secs > 0 {
				h.ExpiresIn = secs
			}
			// Expired or unparseable → leave 0: the session falls back to
			// JWT exp / refresh-on-first-use, which is the correct behavior.
		}
	}
	return h, nil
}

// logoutOldDaemon stops a daemon holding a dead session so a fresh login can
// take its socket, then waits for the process to release the path.
func logoutOldDaemon(sock, sec string) error {
	hc := unixHTTP(sock, 15*time.Second)
	req, err := http.NewRequest(http.MethodPost, takeoverHost+"/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+sec)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("logout of stale daemon failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("logout of stale daemon failed: HTTP %d", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !daemonAlive(sock) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("stale daemon on %s did not stop after logout", sock)
}

// listenWithRetry binds the socket, waiting out a predecessor that is still
// releasing it (takeover / replace window). Non-busy errors fail fast.
func listenWithRetry(sockPath string, wait time.Duration) (net.Listener, error) {
	deadline := time.Now().Add(wait)
	for {
		ln, err := server.ListenUnix(sockPath)
		if err == nil {
			return ln, nil
		}
		if !errors.Is(err, server.ErrSocketInUse) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
