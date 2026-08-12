// Package client is the SDK for the local xai-oauth token sidecar.
//
// Transport is Unix domain socket only (HTTP over AF_UNIX).
// Supported on Linux, macOS, and Windows 10 1803+ / Server 2019+.
//
// The local API secret is read only from the environment variable
// XAI_OAUTH_SECRET (same as the CLI). There is no Config field for it.
//
//	// export XAI_OAUTH_SECRET=…
//	c, err := client.New(client.Config{})
//	tok, err := c.Get(ctx)
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EnvSocket is the Unix socket path for the daemon.
	EnvSocket = "XAI_OAUTH_SOCKET"
	// EnvSecret is the local API secret for authenticated routes.
	// This is the only supported source for the client secret.
	EnvSecret = "XAI_OAUTH_SECRET"

	// httpHost is the synthetic URL origin for HTTP requests over a Unix socket.
	httpHost = "http://xai-oauth.local"

	requestTimeout = 30 * time.Second
)

// Config configures a Client.
type Config struct {
	// SocketPath is the Unix domain socket path.
	// Empty → XAI_OAUTH_SOCKET → DefaultSocketPath().
	SocketPath string
}

// Client talks to a running xai-oauth serve process over a Unix socket.
// It is safe for concurrent use by multiple goroutines.
type Client struct {
	secret string
	http   *http.Client
	socket string
}

// State is the daemon session state as reported by /status and /ready.
type State string

const (
	// StateReady: the session can serve tokens.
	StateReady State = "ready"
	// StateReauthRequired: sticky failure; restart xai-oauth serve and sign in.
	StateReauthRequired State = "reauth_required"
	// StateTierDenied: sticky failure; the account lacks API entitlement.
	StateTierDenied State = "tier_denied"
	// StateDegraded (Ready only): the access token expired and the last
	// refresh failed; self-heals when a refresh succeeds.
	StateDegraded State = "degraded"
	// StateNotReady (Ready only): daemon answered without a usable state.
	StateNotReady State = "not_ready"
)

// New builds a Client. The local secret is required and taken only from
// XAI_OAUTH_SECRET (no Config field).
func New(cfg Config) (*Client, error) {
	secret := strings.TrimSpace(os.Getenv(EnvSecret))
	if secret == "" {
		return nil, fmt.Errorf("xai-oauth client: secret is required (set env %s)", EnvSecret)
	}

	sock := strings.TrimSpace(cfg.SocketPath)
	if sock == "" {
		sock = strings.TrimSpace(os.Getenv(EnvSocket))
	}
	if sock == "" {
		sock = DefaultSocketPath()
	}
	sock = filepath.Clean(sock)
	if sock == "." || sock == string(filepath.Separator) {
		return nil, fmt.Errorf("xai-oauth client: invalid socket path")
	}

	return &Client{
		secret: secret,
		socket: sock,
		http:   unixHTTPClient(sock),
	}, nil
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			// One local daemon behind one synthetic host; keep a small,
			// short-lived idle pool.
			MaxIdleConns:    2,
			IdleConnTimeout: 60 * time.Second,
		},
	}
}

// CloseIdleConnections releases idle daemon connections held by the client.
// The Client remains usable; connections are re-established on demand.
func (c *Client) CloseIdleConnections() {
	if c == nil || c.http == nil {
		return
	}
	c.http.CloseIdleConnections()
}

// SocketPath returns the Unix socket path this client dials.
func (c *Client) SocketPath() string {
	if c == nil {
		return ""
	}
	return c.socket
}

// Get fetches a usable access_token (GET /token). Serve handles refresh.
func (c *Client) Get(ctx context.Context) (string, error) {
	if err := c.require(); err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, status, err := c.doJSON(ctx, http.MethodGet, "/token")
	if err != nil {
		return "", err
	}
	if status == http.StatusOK {
		var ok tokenOK
		if err := json.Unmarshal(body, &ok); err != nil {
			return "", fmt.Errorf("xai-oauth client: invalid token JSON: %w", err)
		}
		if strings.TrimSpace(ok.AccessToken) == "" {
			return "", fmt.Errorf("xai-oauth client: empty access_token")
		}
		return ok.AccessToken, nil
	}
	var er tokenErr
	_ = json.Unmarshal(body, &er)
	return "", mapHTTPError(status, er)
}

// Status is a non-sensitive snapshot from GET /status.
type Status struct {
	State State `json:"state"`
	// HasExpiry reports whether ExpiresAt is known.
	HasExpiry bool `json:"has_expiry"`
	// ExpiresAt is the access-token expiry (zero when !HasExpiry).
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// TokenValid reports whether the daemon's access token is hard-valid
	// right now; false may still mean /token succeeds via refresh.
	TokenValid bool   `json:"token_valid"`
	LastError  string `json:"last_error,omitempty"`
}

// Status calls GET /status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	if err := c.require(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, status, err := c.doJSON(ctx, http.MethodGet, "/status")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		var er tokenErr
		_ = json.Unmarshal(body, &er)
		return nil, mapHTTPError(status, er)
	}
	var st Status
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("xai-oauth client: invalid status JSON: %w", err)
	}
	return &st, nil
}

// Ready calls GET /ready. When not ready, state names the reason:
// StateReauthRequired / StateTierDenied (sticky) or StateDegraded
// (transient refresh failure with an expired token).
func (c *Client) Ready(ctx context.Context) (ready bool, state State, err error) {
	if err := c.require(); err != nil {
		return false, "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, status, err := c.doJSON(ctx, http.MethodGet, "/ready")
	if err != nil {
		return false, "", err
	}
	var out struct {
		Ready bool  `json:"ready"`
		State State `json:"state"`
	}
	_ = json.Unmarshal(body, &out)
	if status == http.StatusOK && out.Ready {
		return true, StateReady, nil
	}
	if out.State == "" {
		out.State = StateNotReady
	}
	return false, out.State, nil
}

// WaitReady polls GET /status until the daemon reports a ready session, ctx
// is done, or a failure that cannot resolve on its own is detected (wrong
// local secret, sticky reauth_required / tier_denied). Useful right after
// starting xai-oauth serve. Transient conditions (daemon not yet listening,
// degraded session) keep polling.
func (c *Client) WaitReady(ctx context.Context) error {
	if err := c.require(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var last error
	for {
		st, err := c.Status(ctx)
		switch {
		case err == nil && st.State == StateReady:
			return nil
		case err == nil:
			switch st.State {
			case StateReauthRequired:
				return fmt.Errorf("%w: daemon state %s", ErrReauthRequired, st.State)
			case StateTierDenied:
				return fmt.Errorf("%w: daemon state %s", ErrTierDenied, st.State)
			}
			last = fmt.Errorf("daemon state %q", st.State)
		case errors.Is(err, ErrUnauthorized):
			return err // wrong secret will not fix itself
		default:
			last = err
		}

		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return fmt.Errorf("wait ready: %w", last)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Logout calls POST /logout (clears session; serve typically exits).
func (c *Client) Logout(ctx context.Context) error {
	if err := c.require(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, status, err := c.doJSON(ctx, http.MethodPost, "/logout")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		var er tokenErr
		_ = json.Unmarshal(body, &er)
		return mapHTTPError(status, er)
	}
	return nil
}

// Health calls GET /health.
func (c *Client) Health(ctx context.Context) error {
	if err := c.require(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, status, err := c.doJSON(ctx, http.MethodGet, "/health")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("xai-oauth client: health HTTP %d", status)
	}
	return nil
}

func (c *Client) require() error {
	if c == nil {
		return fmt.Errorf("xai-oauth client: nil client")
	}
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string) ([]byte, int, error) {
	u := httpHost + path
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("xai-oauth client: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// Transport-level failure: daemon down, bad socket path, refused.
		return nil, 0, fmt.Errorf("%w (socket %s): %v", ErrUnreachable, c.socket, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("xai-oauth client: read body: %w", err)
	}
	return body, resp.StatusCode, nil
}

type tokenOK struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type tokenErr struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func mapHTTPError(status int, er tokenErr) error {
	code := strings.TrimSpace(er.Error)
	msg := strings.TrimSpace(er.Message)
	if msg == "" {
		msg = code
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", status)
	}

	switch {
	case status == http.StatusUnauthorized && code == "reauth_required":
		return fmt.Errorf("%w: %s", ErrReauthRequired, msg)
	case status == http.StatusUnauthorized && (code == "unauthorized" || code == ""):
		return fmt.Errorf("%w: %s", ErrUnauthorized, msg)
	case status == http.StatusForbidden && code == "tier_denied":
		return fmt.Errorf("%w: %s", ErrTierDenied, msg)
	case status == http.StatusServiceUnavailable || code == "unavailable":
		return fmt.Errorf("%w: %s", ErrUnavailable, msg)
	default:
		return fmt.Errorf("xai-oauth client: %s (HTTP %d)", msg, status)
	}
}
