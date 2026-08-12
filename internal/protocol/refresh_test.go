package protocol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testTokenEndpoint = "https://auth.x.ai/oauth2/token"

func TestRefreshOKRotates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("grant_type") != "refresh_token" ||
			r.PostForm.Get("client_id") != ClientID ||
			r.PostForm.Get("refresh_token") != "old-rt" {
			t.Errorf("form = %v", r.PostForm)
		}
		_, _ = w.Write([]byte(`{
			"access_token": "new-at",
			"refresh_token": "new-rt",
			"expires_in": 3600
		}`))
	}))
	defer srv.Close()

	tr, err := Refresh(context.Background(), xaiRewriteClient(srv), testTokenEndpoint, "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "new-at" || tr.RefreshToken != "new-rt" {
		t.Fatalf("tokens: %+v", tr)
	}
	if tr.TokenType != "Bearer" {
		t.Fatalf("token_type = %q", tr.TokenType)
	}
}

func TestRefreshKeepsOldRTWhenNotRotated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token": "new-at", "expires_in": 3600}`))
	}))
	defer srv.Close()

	tr, err := Refresh(context.Background(), xaiRewriteClient(srv), testTokenEndpoint, "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if tr.RefreshToken != "old-rt" {
		t.Fatalf("refresh_token = %q, want retained old-rt", tr.RefreshToken)
	}
}

func TestRefresh403IsTierDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := Refresh(context.Background(), xaiRewriteClient(srv), testTokenEndpoint, "rt")
	if !errors.Is(err, ErrTierDenied) {
		t.Fatalf("err = %v, want tier denied", err)
	}
}

func TestRefreshInvalidGrantIsReauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid_grant", "error_description": "sensitive detail"}`))
	}))
	defer srv.Close()

	_, err := Refresh(context.Background(), xaiRewriteClient(srv), testTokenEndpoint, "rt")
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want reauth", err)
	}
	if got := PublicMessage(err); got != "refresh_failed (HTTP 400)" {
		t.Fatalf("public message %q must not leak the IdP body", got)
	}
}

func TestRefresh5xxIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Refresh(context.Background(), xaiRewriteClient(srv), testTokenEndpoint, "rt")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want transient unavailable", err)
	}
}

func TestRefreshMissingRefreshToken(t *testing.T) {
	_, err := Refresh(context.Background(), nil, testTokenEndpoint, "  ")
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want reauth", err)
	}
}

func TestRefreshRejectsForeignEndpoint(t *testing.T) {
	_, err := Refresh(context.Background(), nil, "https://evil.example/token", "rt")
	if err == nil {
		t.Fatal("expected reject of off-origin endpoint")
	}
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshDiscoversEndpointWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"token_endpoint": "https://auth.x.ai/oauth2/token"}`))
		case "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token": "at", "refresh_token": "rt2", "expires_in": 60}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tr, err := Refresh(context.Background(), xaiRewriteClient(srv), "", "rt")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at" || tr.RefreshToken != "rt2" {
		t.Fatalf("tokens: %+v", tr)
	}
}
