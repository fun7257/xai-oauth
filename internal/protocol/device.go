package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DeviceCodeResponse is the device authorization response.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse is a successful token endpoint payload.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// RequestDeviceCode starts the device-code flow.
func RequestDeviceCode(ctx context.Context, client *http.Client) (*DeviceCodeResponse, error) {
	if client == nil {
		client = defaultIDPClient()
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("scope", Scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, DeviceCodeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, newError("device_code_failed", "device-code request build failed", "transient")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, newError("device_code_failed", "device-code request failed", "transient")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, wrapHTTP("device_code_failed", resp.StatusCode, "transient")
	}

	var dc DeviceCodeResponse
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, newError("device_code_invalid", "invalid device-code JSON", "transient")
	}
	if dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" ||
		dc.ExpiresIn <= 0 || dc.Interval <= 0 {
		return nil, newError("device_code_invalid", "device-code response missing required fields", "transient")
	}
	if err := ValidateUserCode(dc.UserCode); err != nil {
		return nil, newError("device_code_invalid", err.Error(), "transient")
	}
	if err := ValidateVerificationURI(dc.VerificationURI); err != nil {
		return nil, newError("device_code_invalid", err.Error(), "transient")
	}
	if dc.VerificationURIComplete != "" {
		if err := ValidateVerificationURI(dc.VerificationURIComplete); err != nil {
			return nil, newError("device_code_invalid", err.Error(), "transient")
		}
	}
	return &dc, nil
}

// PollDeviceToken polls until the user approves or the code expires.
func PollDeviceToken(ctx context.Context, client *http.Client, tokenEndpoint, deviceCode string, expiresIn, interval int) (*TokenResponse, error) {
	if client == nil {
		client = defaultIDPClient()
	}
	if err := ValidateXAIURL(tokenEndpoint, "token_endpoint"); err != nil {
		return nil, newError("discovery_invalid", err.Error(), "reauth")
	}
	deadline := time.Now().Add(deviceAuthWindow(expiresIn))
	currentInterval := clampPollInterval(interval)

	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("client_id", ClientID)
		form.Set("device_code", deviceCode)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, newError("device_token_failed", "token poll request build failed", "transient")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, newError("device_token_failed", "token poll failed", "transient")
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var tr TokenResponse
			if err := json.Unmarshal(body, &tr); err != nil {
				return nil, newError("device_token_invalid", "invalid token JSON", "transient")
			}
			if strings.TrimSpace(tr.AccessToken) == "" {
				return nil, newError("device_token_invalid", "token response missing access_token", "reauth")
			}
			if strings.TrimSpace(tr.RefreshToken) == "" {
				return nil, newError("device_token_invalid", "token response missing refresh_token", "reauth")
			}
			if tr.TokenType == "" {
				tr.TokenType = "Bearer"
			}
			return &tr, nil
		}

		var errPayload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &errPayload)
		// Normalize like refresh (parseOAuthError / sanitizeOAuthErrorCode).
		code := sanitizeOAuthErrorCode(errPayload.Error)
		switch code {
		case "authorization_pending":
			if err := sleepCtx(ctx, time.Duration(currentInterval)*time.Second); err != nil {
				return nil, err
			}
			continue
		case "slow_down":
			currentInterval = clampPollInterval(currentInterval + 1)
			if err := sleepCtx(ctx, time.Duration(currentInterval)*time.Second); err != nil {
				return nil, err
			}
			continue
		default:
			// Public message: sanitized oauth error code only, never response body.
			if code == "" {
				return nil, newError("device_token_failed", "device-code token polling failed", "reauth")
			}
			return nil, newError("device_token_failed", "device-code token polling failed: "+code, "reauth")
		}
	}
	return nil, newError("device_timeout", "timed out waiting for device authorization", "reauth")
}

// deviceAuthWindow bounds the total poll window: the IdP-provided expires_in,
// capped at MaxDeviceAuthWindow so a bogus upstream value cannot pin the
// process in the poll loop for hours (library callers may lack the CLI's
// outer login timeout).
func deviceAuthWindow(expiresIn int) time.Duration {
	w := time.Duration(expiresIn) * time.Second
	if w > MaxDeviceAuthWindow {
		return MaxDeviceAuthWindow
	}
	return w
}

// clampPollInterval bounds a poll interval in seconds to [1, MaxDevicePollInterval].
func clampPollInterval(seconds int) int {
	if seconds < 1 {
		return 1
	}
	if maxSec := int(MaxDevicePollInterval / time.Second); seconds > maxSec {
		return maxSec
	}
	return seconds
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// LoginResult is a successful device-code login.
type LoginResult struct {
	Tokens    TokenResponse
	Discovery Discovery
}

// DeviceLogin runs discovery → device code → poll.
func DeviceLogin(ctx context.Context, client *http.Client, openBrowser bool, printFn func(string)) (*LoginResult, error) {
	if printFn == nil {
		printFn = func(s string) { fmt.Fprintln(os.Stderr, s) }
	}
	disc, err := Discover(ctx, client)
	if err != nil {
		return nil, err
	}
	dc, err := RequestDeviceCode(ctx, client)
	if err != nil {
		return nil, err
	}

	verify := dc.VerificationURIComplete
	if verify == "" {
		verify = dc.VerificationURI
	}
	printFn("")
	printFn("To continue:")
	printFn("  1. Open: " + verify)
	printFn("  2. If prompted, enter code: " + dc.UserCode)
	if openBrowser {
		if tryOpenBrowser(verify) {
			printFn("  (Opened browser for verification)")
		} else {
			printFn("  Could not open browser automatically — use the URL above.")
		}
	}
	printFn(fmt.Sprintf("Waiting for approval (polling every %ds)...", max(1, dc.Interval)))

	tr, err := PollDeviceToken(ctx, client, disc.TokenEndpoint, dc.DeviceCode, dc.ExpiresIn, dc.Interval)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Tokens: *tr, Discovery: *disc}, nil
}

func tryOpenBrowser(u string) bool {
	// Linux/macOS only (this project does not support Windows).
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		cmd = exec.Command("xdg-open", u)
	default:
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	// Reap the helper so Start does not leave an unreaped child.
	go func() { _ = cmd.Wait() }()
	return true
}
