package protocol

import (
	"fmt"
	"net/http"
	"time"
)

// NewIDPClient builds an HTTP client for egress to auth.x.ai.
// Redirects are re-validated against the x.ai host pin so refresh_token /
// device_code POSTs are not replayed to an untrusted Location.
func NewIDPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = IDPRequestTimeout
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkIDPRedirect,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
}

func checkIDPRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("stopped after 5 redirects")
	}
	if req.URL == nil {
		return fmt.Errorf("redirect missing URL")
	}
	// Absolute URL of the next hop (Go sets this on the request).
	if err := ValidateXAIURL(req.URL.String(), "redirect"); err != nil {
		return fmt.Errorf("redirect rejected: %w", err)
	}
	return nil
}

// defaultIDPClient is used when callers pass a nil *http.Client.
func defaultIDPClient() *http.Client {
	return NewIDPClient(IDPRequestTimeout)
}
