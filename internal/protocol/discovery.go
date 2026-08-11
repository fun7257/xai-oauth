package protocol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// Discovery holds OIDC endpoints from auth.x.ai.
type Discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// Discover fetches and validates the OIDC configuration.
func Discover(ctx context.Context, client *http.Client) (*Discovery, error) {
	if client == nil {
		client = defaultIDPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DiscoveryURL, nil)
	if err != nil {
		return nil, newError("discovery_failed", "discovery request build failed", "transient")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, newError("discovery_failed", "OIDC discovery request failed", "transient")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, wrapHTTP("discovery_failed", resp.StatusCode, "transient")
	}

	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, newError("discovery_invalid", "invalid discovery JSON", "transient")
	}
	if d.TokenEndpoint == "" {
		return nil, newError("discovery_invalid", "discovery missing token_endpoint", "transient")
	}
	if err := ValidateXAIURL(d.TokenEndpoint, "token_endpoint"); err != nil {
		return nil, newError("discovery_invalid", "token_endpoint failed validation", "transient")
	}
	if d.AuthorizationEndpoint != "" {
		if err := ValidateXAIURL(d.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
			return nil, newError("discovery_invalid", "authorization_endpoint failed validation", "transient")
		}
	}
	return &d, nil
}
