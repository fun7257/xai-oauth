package client

import (
	"fmt"
	"net/http"

	"github.com/fun7257/xai-oauth/internal/protocol"
)

// Transport returns an http.RoundTripper that fetches a token from the
// sidecar and sets "Authorization: Bearer <access_token>" on each outgoing
// request bound for https on x.ai or a true subdomain (api.x.ai, …). The
// daemon caches and proactively refreshes, so the per-request fetch is a
// cheap local socket round-trip that always yields a usable token.
//
// Requests to any other scheme or host pass through unchanged and never
// trigger a token fetch, so the OAuth bearer cannot leak to foreign origins.
// A request that already carries an Authorization header is passed through
// untouched. base defaults to http.DefaultTransport.
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &bearerTransport{c: c, base: base}
}

// HTTPClient returns an *http.Client wired with Transport(nil):
//
//	hc := c.HTTPClient()
//	resp, err := hc.Get("https://api.x.ai/v1/models")
//
// Timeouts and other policies are the caller's to configure on the returned
// client; only the transport is preset.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{Transport: c.Transport(nil)}
}

type bearerTransport struct {
	c    *Client
	base http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !bearerEligible(req) {
		return t.base.RoundTrip(req)
	}
	tok, err := t.c.Get(req.Context())
	if err != nil {
		return nil, fmt.Errorf("xai-oauth transport: %w", err)
	}
	// RoundTrippers must not mutate the caller's request.
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(req2)
}

// bearerEligible restricts token injection to https on pinned x.ai hosts,
// leaving explicit caller Authorization headers alone.
func bearerEligible(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if req.URL.Scheme != "https" {
		return false
	}
	if req.Header.Get("Authorization") != "" {
		return false
	}
	return protocol.IsXAIHost(req.URL.Hostname())
}
