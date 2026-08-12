package protocol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// xaiRewriteClient returns an *http.Client whose requests keep pin-checkable
// https://…x.ai URLs but are transparently delivered to the local test server.
func xaiRewriteClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req2 := req.Clone(req.Context())
			req2.URL.Scheme = "http"
			req2.URL.Host = srv.Listener.Addr().String()
			req2.RequestURI = ""
			return http.DefaultTransport.RoundTrip(req2)
		}),
		Timeout: 5 * time.Second,
	}
}

func TestDiscoverOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"token_endpoint": "https://auth.x.ai/oauth2/token",
			"authorization_endpoint": "https://auth.x.ai/oauth2/authorize"
		}`))
	}))
	defer srv.Close()

	d, err := Discover(context.Background(), xaiRewriteClient(srv))
	if err != nil {
		t.Fatal(err)
	}
	if d.TokenEndpoint != "https://auth.x.ai/oauth2/token" {
		t.Fatalf("token_endpoint = %q", d.TokenEndpoint)
	}
}

func TestDiscoverRejectsForeignTokenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_endpoint": "https://evil.example/oauth2/token"}`))
	}))
	defer srv.Close()

	_, err := Discover(context.Background(), xaiRewriteClient(srv))
	if err == nil {
		t.Fatal("expected reject of off-origin token_endpoint")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("kind: %v", err)
	}
}

func TestDiscoverRejectsForeignAuthorizationEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"token_endpoint": "https://auth.x.ai/oauth2/token",
			"authorization_endpoint": "https://evil.notx.ai/authorize"
		}`))
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), xaiRewriteClient(srv)); err == nil {
		t.Fatal("expected reject of off-origin authorization_endpoint")
	}
}

func TestDiscoverMissingTokenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), xaiRewriteClient(srv)); err == nil {
		t.Fatal("expected missing token_endpoint error")
	}
}

func TestDiscoverHTTPErrorIsSanitized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream secret detail`))
	}))
	defer srv.Close()

	_, err := Discover(context.Background(), xaiRewriteClient(srv))
	if err == nil {
		t.Fatal("expected error on HTTP 502")
	}
	var pe *Error
	if !errors.As(err, &pe) || pe.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("err = %#v", err)
	}
	if got := PublicMessage(err); got != "discovery_failed (HTTP 502)" {
		t.Fatalf("public message %q leaks detail", got)
	}
}
