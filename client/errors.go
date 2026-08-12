package client

import "errors"

// Sentinel errors returned by Client methods (match with errors.Is).
var (
	// ErrUnreachable means the daemon socket could not be reached at the
	// transport level (daemon not running, wrong socket path, connection
	// refused). Start it with: xai-oauth serve.
	ErrUnreachable = errors.New("xai-oauth daemon unreachable")
	// ErrUnauthorized means the local secret was rejected.
	ErrUnauthorized = errors.New("xai-oauth unauthorized")
	// ErrReauthRequired means the sidecar needs a fresh device login (restart xai-oauth serve).
	ErrReauthRequired = errors.New("xai-oauth reauth required")
	// ErrTierDenied means the OAuth account is not entitled for API access.
	ErrTierDenied = errors.New("xai-oauth tier denied")
	// ErrUnavailable means a transient sidecar/IdP failure; retry later.
	ErrUnavailable = errors.New("xai-oauth unavailable")
)
