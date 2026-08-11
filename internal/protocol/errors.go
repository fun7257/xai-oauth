package protocol

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for session / HTTP mapping.
var (
	ErrReauthRequired = errors.New("reauth required")
	ErrTierDenied     = errors.New("tier denied")
	ErrUnavailable    = errors.New("temporarily unavailable")
	ErrUnauthorized   = errors.New("unauthorized")
)

// Error is a protocol-layer failure.
// Message is safe for logs/status: stable code + HTTP status only — never IdP body or tokens.
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	// Kind: "" | reauth | tier | transient
	Kind string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case "reauth":
		return ErrReauthRequired
	case "tier":
		return ErrTierDenied
	case "transient":
		return ErrUnavailable
	default:
		return nil
	}
}

// PublicMessage returns a short, non-sensitive string for /status last_error.
func PublicMessage(err error) string {
	if err == nil {
		return ""
	}
	var pe *Error
	if errors.As(err, &pe) && pe != nil {
		if pe.Code != "" {
			if pe.HTTPStatus > 0 {
				return fmt.Sprintf("%s (HTTP %d)", pe.Code, pe.HTTPStatus)
			}
			return pe.Code
		}
	}
	switch {
	case errors.Is(err, ErrReauthRequired):
		return "reauth_required"
	case errors.Is(err, ErrTierDenied):
		return "tier_denied"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	default:
		// Do not surface arbitrary error strings (may wrap network detail).
		return "error"
	}
}

func newError(code, msg, kind string) *Error {
	// Prefer code as public message when msg is free-form.
	public := code
	if msg != "" && msg != code {
		// Keep human context only if it cannot reasonably contain wire bodies:
		// callers must pass short fixed phrases, not response bodies.
		public = msg
	}
	return &Error{Code: code, Message: public, Kind: kind}
}

func wrapHTTP(code string, status int, kind string) *Error {
	return &Error{
		Code:       code,
		Message:    fmt.Sprintf("%s (HTTP %d)", code, status),
		HTTPStatus: status,
		Kind:       kind,
	}
}

// sanitizeOAuthErrorCode returns a short safe oauth2 error code for messages,
// or "" if the value is not a well-formed code (max 64 of [a-z0-9_]).
func sanitizeOAuthErrorCode(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || len(raw) > 64 {
		return ""
	}
	for _, r := range raw {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return ""
		}
	}
	return raw
}
