package protocol

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

const (
	// MaxUserCodeLen bounds device user_code length (anti log/DoS flood).
	MaxUserCodeLen = 64
	// MaxVerificationURILen bounds verification URLs before print/open.
	MaxVerificationURILen = 2048
)

// isXAIHost reports whether host is x.ai or a true subdomain of x.ai.
// Uses DNS labels (last two must be "x" and "ai") so that evil.notx.ai is rejected.
func isXAIHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	// Reject empty labels / leading dots after normalize.
	if strings.Contains(h, "..") || strings.HasPrefix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	n := len(labels)
	if n < 2 {
		return false
	}
	for _, lab := range labels {
		if lab == "" {
			return false
		}
	}
	return labels[n-2] == "x" && labels[n-1] == "ai"
}

// ValidateXAIURL requires https and host x.ai or a subdomain of x.ai.
func ValidateXAIURL(raw, field string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(raw) > MaxVerificationURILen {
		return fmt.Errorf("%s exceeds max length", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use https (got %q)", field, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%s is missing a hostname", field)
	}
	if !isXAIHost(host) {
		return fmt.Errorf("%s host %q is not on the x.ai origin", field, host)
	}
	return nil
}

// ValidateUserCode rejects control characters, non [A-Za-z0-9-], and oversize codes.
func ValidateUserCode(code string) error {
	if code == "" {
		return fmt.Errorf("user_code is empty")
	}
	if len(code) > MaxUserCodeLen {
		return fmt.Errorf("user_code exceeds max length")
	}
	for _, r := range code {
		if r > unicode.MaxASCII || unicode.IsControl(r) {
			return fmt.Errorf("user_code contains invalid characters")
		}
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("user_code contains invalid characters")
		}
	}
	return nil
}

// ValidateVerificationURI ensures the device-flow browser URL is safe to print/open.
// Production: https on x.ai / true subdomains of x.ai only.
func ValidateVerificationURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("verification URI is empty")
	}
	if len(raw) > MaxVerificationURILen {
		return fmt.Errorf("verification URI exceeds max length")
	}
	for _, r := range raw {
		if r < 32 || r == 127 {
			return fmt.Errorf("verification URI contains control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("verification URI is not a valid URL")
	}
	switch u.Scheme {
	case "https":
		host := strings.ToLower(u.Hostname())
		if !isXAIHost(host) {
			return fmt.Errorf("verification URI host %q is not on the x.ai origin", host)
		}
		return nil
	default:
		return fmt.Errorf("verification URI must use https")
	}
}
