package client

import "errors"

// Sentinel errors returned by Client.Get (via errors.Is).
var (
	// ErrUnauthorized means the local secret was rejected.
	ErrUnauthorized = errors.New("xai-oauth unauthorized")
	// ErrReauthRequired means the sidecar needs a fresh device login (restart xai-oauth serve).
	ErrReauthRequired = errors.New("xai-oauth reauth required")
	// ErrTierDenied means the OAuth account is not entitled for API access.
	ErrTierDenied = errors.New("xai-oauth tier denied")
	// ErrUnavailable means a transient sidecar/IdP failure; retry later.
	ErrUnavailable = errors.New("xai-oauth unavailable")
)
