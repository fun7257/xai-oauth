package protocol

import "time"

// xAI OAuth2 personal (device client). Client ID matches grok-build / xai-proxy.
const (
	Issuer        = "https://auth.x.ai"
	DiscoveryURL  = Issuer + "/.well-known/openid-configuration"
	DeviceCodeURL = Issuer + "/oauth2/device/code"
	ClientID      = "b1a00492-073a-47ea-816f-4c329264a828"

	// Scope is fixed to grok-build default_oauth2_scopes (personal). Not configurable.
	Scope = "openid profile email offline_access grok-cli:access api:access " +
		"conversations:read conversations:write workspaces:read workspaces:write"

	DefaultTokenURL = Issuer + "/oauth2/token"

	// RefreshSkew is the proactive refresh window before ExpiresAt.
	RefreshSkew = 5 * time.Minute

	// IDPRequestTimeout bounds a single discovery / device / refresh HTTP call.
	IDPRequestTimeout = 20 * time.Second
)
