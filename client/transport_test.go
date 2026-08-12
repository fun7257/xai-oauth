package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// tokenDaemon serves GET /token and counts hits.
func tokenDaemon(t *testing.T, token string, hits *int) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		*hits++
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": token,
			"token_type":   "Bearer",
		})
	})
	return startUnixDaemon(t, mux)
}

func newTransportClient(t *testing.T, sock string) *Client {
	t.Helper()
	t.Setenv(EnvSecret, "s")
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func roundTripVia(t *testing.T, c *Client, req *http.Request) (sent *http.Request) {
	t.Helper()
	rt := c.Transport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = r
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{}")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	}))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()
	return sent
}

func TestTransportInjectsBearerForXAI(t *testing.T) {
	var hits int
	sock := tokenDaemon(t, "at-42", &hits)
	c := newTransportClient(t, sock)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.x.ai/v1/models", nil)
	sent := roundTripVia(t, c, req)

	if got := sent.Header.Get("Authorization"); got != "Bearer at-42" {
		t.Fatalf("Authorization = %q", got)
	}
	if hits != 1 {
		t.Fatalf("token fetches = %d, want 1", hits)
	}
	// RoundTrippers must not mutate the caller's request.
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("original request mutated: Authorization = %q", got)
	}
}

func TestTransportSkipsForeignAndInsecureHosts(t *testing.T) {
	var hits int
	sock := tokenDaemon(t, "at-42", &hits)
	c := newTransportClient(t, sock)

	for _, u := range []string{
		"https://evil.example/v1/models",
		"https://evil.notx.ai/v1/models",
		"http://api.x.ai/v1/models", // https required
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		sent := roundTripVia(t, c, req)
		if got := sent.Header.Get("Authorization"); got != "" {
			t.Fatalf("%s: unexpected Authorization %q", u, got)
		}
	}
	if hits != 0 {
		t.Fatalf("token fetches = %d, want 0 (no fetch for ineligible requests)", hits)
	}
}

func TestTransportKeepsCallerAuthorization(t *testing.T) {
	var hits int
	sock := tokenDaemon(t, "at-42", &hits)
	c := newTransportClient(t, sock)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.x.ai/v1/models", nil)
	req.Header.Set("Authorization", "Bearer caller-owned")
	sent := roundTripVia(t, c, req)

	if got := sent.Header.Get("Authorization"); got != "Bearer caller-owned" {
		t.Fatalf("Authorization = %q, want caller header preserved", got)
	}
	if hits != 0 {
		t.Fatalf("token fetches = %d, want 0", hits)
	}
}

func TestHTTPClientWiresTransport(t *testing.T) {
	var hits int
	sock := tokenDaemon(t, "at-42", &hits)
	c := newTransportClient(t, sock)

	hc := c.HTTPClient()
	if _, ok := hc.Transport.(*bearerTransport); !ok {
		t.Fatalf("Transport type = %T", hc.Transport)
	}
}
