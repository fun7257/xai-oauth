package protocol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Refresh exchanges refresh_token for a new access token (and rotated refresh when returned).
func Refresh(ctx context.Context, client *http.Client, tokenEndpoint, refreshToken string) (*TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, newError("missing_refresh", "missing refresh_token", "reauth")
	}
	endpoint := strings.TrimSpace(tokenEndpoint)
	if endpoint == "" {
		d, err := Discover(ctx, client)
		if err != nil {
			return nil, err
		}
		endpoint = d.TokenEndpoint
	}
	if err := ValidateXAIURL(endpoint, "token_endpoint"); err != nil {
		return nil, newError("discovery_invalid", "token_endpoint failed validation", "reauth")
	}
	if client == nil {
		client = &http.Client{Timeout: IDPRequestTimeout}
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", ClientID)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, newError("refresh_failed", "refresh request build failed", "transient")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, newError("refresh_failed", "token refresh request failed", "transient")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusForbidden {
		return nil, &Error{
			Code:       "tier_denied",
			Message:    "xai_oauth_tier_denied (HTTP 403)",
			HTTPStatus: 403,
			Kind:       "tier",
		}
	}

	if resp.StatusCode != http.StatusOK {
		kind := "transient"
		oauthErr := parseOAuthError(body)
		if oauthErr == "invalid_grant" || oauthErr == "invalid_client" {
			kind = "reauth"
		}
		return nil, wrapHTTP("refresh_failed", resp.StatusCode, kind)
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, newError("refresh_failed", "invalid refresh JSON", "transient")
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return nil, newError("missing_access", "refresh response missing access_token", "reauth")
	}
	if strings.TrimSpace(tr.RefreshToken) == "" {
		tr.RefreshToken = refreshToken
	}
	if tr.TokenType == "" {
		tr.TokenType = "Bearer"
	}
	return &tr, nil
}

func parseOAuthError(body []byte) string {
	var p struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &p) != nil {
		return ""
	}
	return sanitizeOAuthErrorCode(p.Error)
}
