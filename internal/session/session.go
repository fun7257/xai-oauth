package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

// State is the session lifecycle.
type State string

const (
	StateReady          State = "ready"
	StateReauthRequired State = "reauth_required"
	StateTierDenied     State = "tier_denied"
	// StateHandedOff: the session was transferred to a successor process
	// (serve takeover). This process is shutting down; token requests fail
	// with unavailable so clients retry against the successor.
	StateHandedOff State = "handed_off"
)

// refreshFunc is the IdP refresh call. Tests inject a stub; production uses protocol.Refresh.
type refreshFunc func(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*protocol.TokenResponse, error)

// Session holds in-memory OAuth credentials for one process.
type Session struct {
	mu sync.Mutex

	// opMu serializes IdP refresh calls with handoff drains so a handoff
	// snapshot can never race a refresh-token rotation (a snapshot taken
	// mid-refresh would hand out an already-consumed RT).
	opMu sync.Mutex

	client *http.Client

	accessToken   string
	refreshToken  string
	tokenEndpoint string
	expiresAt     time.Time
	hasExpiry     bool // false → refresh on every GetAccessToken
	state         State
	lastError     string

	// refresher defaults to protocol.Refresh when nil.
	refresher refreshFunc

	sf singleflight
}

// NewFromLogin builds a ready session from a successful device login.
func NewFromLogin(client *http.Client, result *protocol.LoginResult) (*Session, error) {
	if client == nil {
		client = protocol.NewIDPClient(protocol.IDPRequestTimeout)
	}
	if result == nil {
		return nil, errors.New("nil login result")
	}
	tr := result.Tokens
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		return nil, errors.New("login missing access or refresh token")
	}
	ep := result.Discovery.TokenEndpoint
	if err := protocol.ValidateXAIURL(ep, "token_endpoint"); err != nil {
		return nil, err
	}
	exp, ok := protocol.ExpiresAtFromToken(tr.AccessToken, tr.ExpiresIn, time.Now())
	return &Session{
		client:        client,
		accessToken:   tr.AccessToken,
		refreshToken:  tr.RefreshToken,
		tokenEndpoint: ep,
		expiresAt:     exp,
		hasExpiry:     ok,
		state:         StateReady,
	}, nil
}

// Status is a non-sensitive snapshot.
type Status struct {
	State     State     `json:"state"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	HasExpiry bool      `json:"has_expiry"`
	// TokenValid reports whether the held access token is hard-valid right
	// now (not past expiry). False does not imply failure: /token may still
	// succeed via refresh.
	TokenValid bool   `json:"token_valid"`
	LastError  string `json:"last_error,omitempty"`
}

// Status returns a non-sensitive snapshot.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		State:      s.state,
		HasExpiry:  s.hasExpiry,
		TokenValid: s.hardValidLocked(),
		LastError:  s.lastError,
	}
	if s.hasExpiry {
		st.ExpiresAt = s.expiresAt
	}
	return st
}

// ReadyReasonDegraded is reported by Ready when the state is nominally ready
// but the access token has expired and the last refresh attempt failed, so
// GET /token is likely to fail until the IdP recovers.
const ReadyReasonDegraded = "degraded"

// Ready reports whether GET /token can plausibly succeed right now:
// state is ready, and either the access token is still hard-valid or no
// refresh failure has been recorded. When not ready, reason is the sticky
// state (reauth_required / tier_denied) or ReadyReasonDegraded.
func (s *Session) Ready() (ready bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateReady {
		return false, string(s.state)
	}
	if s.hardValidLocked() || s.lastError == "" {
		return true, string(StateReady)
	}
	return false, ReadyReasonDegraded
}

// HandoffData is a snapshot of live session credentials for process takeover
// (POST /handoff). It contains the refresh token — handle it like the session
// itself: memory only, never persisted, zero out after use.
type HandoffData struct {
	AccessToken   string
	RefreshToken  string
	TokenEndpoint string
	ExpiresAt     time.Time
	HasExpiry     bool
}

// Handoff drains the session for takeover by a successor process. It waits
// for any in-flight refresh to complete first (a snapshot taken mid-refresh
// could capture an already-consumed rotated refresh token), then wipes the
// credentials from this session, marks the state handed_off (token requests
// fail unavailable so clients retry against the successor), and returns the
// snapshot. When the session is not ready, the current state is returned so
// callers can report it. Use RestoreHandoff to roll back when the snapshot
// cannot be delivered.
func (s *Session) Handoff() (*HandoffData, State, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateReady {
		return nil, s.state, fmt.Errorf("session not ready for handoff (state %s)", s.state)
	}
	d := &HandoffData{
		AccessToken:   s.accessToken,
		RefreshToken:  s.refreshToken,
		TokenEndpoint: s.tokenEndpoint,
		ExpiresAt:     s.expiresAt,
		HasExpiry:     s.hasExpiry,
	}
	s.accessToken = ""
	s.refreshToken = ""
	s.tokenEndpoint = ""
	s.expiresAt = time.Time{}
	s.hasExpiry = false
	s.state = StateHandedOff
	s.lastError = "handed_off"
	return d, StateHandedOff, nil
}

// RestoreHandoff reinstates credentials after a failed handoff delivery so
// this process keeps serving. It is a no-op unless the session is still in
// handed_off — a logout that raced the handoff must not be resurrected.
func (s *Session) RestoreHandoff(d *HandoffData) {
	if d == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateHandedOff {
		return
	}
	s.accessToken = d.AccessToken
	s.refreshToken = d.RefreshToken
	s.tokenEndpoint = d.TokenEndpoint
	s.expiresAt = d.ExpiresAt
	s.hasExpiry = d.HasExpiry
	s.state = StateReady
	s.lastError = ""
}

// Clear wipes credentials from memory (logout). Subsequent GetAccessToken fails with reauth.
func (s *Session) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = ""
	s.refreshToken = ""
	s.tokenEndpoint = ""
	s.expiresAt = time.Time{}
	s.hasExpiry = false
	s.state = StateReauthRequired
	s.lastError = "logged_out"
}

// GetAccessToken returns a usable access token, refreshing when near expiry.
func (s *Session) GetAccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	switch s.state {
	case StateReauthRequired:
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	case StateTierDenied:
		s.mu.Unlock()
		return "", protocol.ErrTierDenied
	case StateHandedOff:
		s.mu.Unlock()
		return "", protocol.ErrUnavailable
	}
	if s.accessStillFreshLocked() {
		tok := s.accessToken
		s.mu.Unlock()
		return tok, nil
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do("token", func() (any, error) {
		return s.refreshIfNeeded(ctx)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (s *Session) accessStillFreshLocked() bool {
	if s.accessToken == "" {
		return false
	}
	if !s.hasExpiry {
		return false // must refresh every time
	}
	return time.Now().Before(s.expiresAt.Add(-protocol.RefreshSkew))
}

func (s *Session) hardValidLocked() bool {
	if s.accessToken == "" {
		return false
	}
	if !s.hasExpiry {
		return false
	}
	return time.Now().Before(s.expiresAt)
}

func (s *Session) refreshIfNeeded(ctx context.Context) (string, error) {
	// Serialize with Handoff: a drain must wait for this refresh to finish
	// (or start only before/after it), never interleave with the IdP call.
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	switch s.state {
	case StateReauthRequired:
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	case StateTierDenied:
		s.mu.Unlock()
		return "", protocol.ErrTierDenied
	case StateHandedOff:
		s.mu.Unlock()
		return "", protocol.ErrUnavailable
	}
	if s.accessStillFreshLocked() {
		tok := s.accessToken
		s.mu.Unlock()
		return tok, nil
	}
	rt := s.refreshToken
	ep := s.tokenEndpoint
	s.mu.Unlock()

	if rt == "" {
		s.mu.Lock()
		s.state = StateReauthRequired
		s.lastError = "missing_refresh"
		s.accessToken = ""
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	}

	refresh := s.refresher
	if refresh == nil {
		refresh = protocol.Refresh
	}
	tr, err := refresh(ctx, s.client, ep, rt)
	if err != nil {
		return s.handleRefreshErr(err)
	}

	exp, ok := protocol.ExpiresAtFromToken(tr.AccessToken, tr.ExpiresIn, time.Now())
	s.mu.Lock()
	// Clear (or sticky reauth/tier) may have won while the IdP call was in flight.
	// Do not resurrect tokens after logout or terminal failure. (Handoff cannot
	// interleave here — it waits on opMu — but check defensively.)
	switch s.state {
	case StateReauthRequired:
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	case StateTierDenied:
		s.mu.Unlock()
		return "", protocol.ErrTierDenied
	case StateHandedOff:
		s.mu.Unlock()
		return "", protocol.ErrUnavailable
	}
	if s.refreshToken == "" {
		s.state = StateReauthRequired
		s.lastError = "logged_out"
		s.accessToken = ""
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	}
	s.accessToken = tr.AccessToken
	s.refreshToken = tr.RefreshToken
	s.expiresAt = exp
	s.hasExpiry = ok
	s.state = StateReady
	s.lastError = ""
	tok := s.accessToken
	s.mu.Unlock()
	return tok, nil
}

func (s *Session) handleRefreshErr(err error) (string, error) {
	pub := protocol.PublicMessage(err)
	var pe *protocol.Error
	if errors.As(err, &pe) {
		switch pe.Kind {
		case "reauth":
			s.mu.Lock()
			s.state = StateReauthRequired
			s.lastError = pub
			s.accessToken = ""
			s.refreshToken = ""
			s.mu.Unlock()
			return "", protocol.ErrReauthRequired
		case "tier":
			s.mu.Lock()
			s.state = StateTierDenied
			s.lastError = pub
			s.accessToken = ""
			s.refreshToken = ""
			s.mu.Unlock()
			return "", protocol.ErrTierDenied
		}
	}
	if errors.Is(err, protocol.ErrReauthRequired) {
		s.mu.Lock()
		s.state = StateReauthRequired
		s.lastError = pub
		s.accessToken = ""
		s.refreshToken = ""
		s.mu.Unlock()
		return "", protocol.ErrReauthRequired
	}
	if errors.Is(err, protocol.ErrTierDenied) {
		s.mu.Lock()
		s.state = StateTierDenied
		s.lastError = pub
		s.accessToken = ""
		s.refreshToken = ""
		s.mu.Unlock()
		return "", protocol.ErrTierDenied
	}

	// Transient: keep RT; return AT if still hard-valid.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = pub
	if s.hardValidLocked() {
		return s.accessToken, nil
	}
	return "", fmt.Errorf("%w: %s", protocol.ErrUnavailable, pub)
}

// --- singleflight ---

type singleflight struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Do runs fn once per key; concurrent callers block and share the leader's
// result. Late joiners cannot cancel via their own context — they wait on the
// leader's call, bounded in practice by the IdP client timeout and the
// caller-side HTTP timeouts.
func (g *singleflight) Do(key string, fn func() (any, error)) (any, error, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				c.err = fmt.Errorf("session refresh panic: %v", rec)
			}
			c.wg.Done()
			g.mu.Lock()
			delete(g.m, key)
			g.mu.Unlock()
		}()
		c.val, c.err = fn()
	}()
	return c.val, c.err, false
}
