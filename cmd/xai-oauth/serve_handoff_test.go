//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/server"
	"github.com/fun7257/xai-oauth/internal/session"
)

func TestLoginHandoffJSONRoundTrip(t *testing.T) {
	h := &loginHandoff{
		Secret:        "sec",
		AccessToken:   "at",
		RefreshToken:  "rt",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
		ExpiresIn:     3600,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(h); err != nil {
		t.Fatal(err)
	}
	var got loginHandoff
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Secret != "sec" || got.AccessToken != "at" || got.RefreshToken != "rt" || got.ExpiresIn != 3600 {
		t.Fatalf("got %+v", got)
	}
	if !strings.HasPrefix(got.TokenEndpoint, "https://auth.x.ai/") {
		t.Fatalf("endpoint %q", got.TokenEndpoint)
	}
}

func TestZeroHandoff(t *testing.T) {
	h := &loginHandoff{Secret: "s", AccessToken: "a", RefreshToken: "r", TokenEndpoint: "e", ExpiresIn: 1}
	zeroHandoff(h)
	if h.Secret != "" || h.AccessToken != "" || h.RefreshToken != "" || h.TokenEndpoint != "" || h.ExpiresIn != 0 {
		t.Fatalf("not zeroed: %+v", h)
	}
}

func TestSessionFromHandoffOK(t *testing.T) {
	h := loginHandoff{
		Secret:        "local-secret",
		AccessToken:   "at",
		RefreshToken:  "rt",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
		ExpiresIn:     3600,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(h); err != nil {
		t.Fatal(err)
	}
	sess, sec, err := sessionFromHandoff(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if sec != "local-secret" {
		t.Fatalf("secret %q", sec)
	}
	if sess.Status().State != session.StateReady {
		t.Fatalf("state %s", sess.Status().State)
	}
}

func TestSessionFromHandoffMissingSecret(t *testing.T) {
	h := loginHandoff{
		AccessToken:   "at",
		RefreshToken:  "rt",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
		ExpiresIn:     3600,
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(h)
	if _, _, err := sessionFromHandoff(&buf); err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestSessionFromHandoffBadEndpoint(t *testing.T) {
	h := loginHandoff{
		Secret:        "sec",
		AccessToken:   "at",
		RefreshToken:  "rt",
		TokenEndpoint: "https://evil.example/token",
		ExpiresIn:     3600,
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(h)
	if _, _, err := sessionFromHandoff(&buf); err == nil {
		t.Fatal("expected bad endpoint error")
	}
}

func TestWaitDaemonReadyRequiresAuth(t *testing.T) {
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	const wantSecret = "right-secret"

	// Unauthenticated-only listener (like a foreign /health-only process).
	ln, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		_ = httpSrv.Close()
		server.RemoveUnixSocket(sock)
	})

	// Old waitDaemonReady would succeed on /health; new one must fail.
	err = waitDaemonReady(sock, wantSecret, 400*time.Millisecond)
	if err == nil {
		t.Fatal("expected ready to fail against unauthenticated listener")
	}
}

func TestWaitDaemonReadyWithStatus(t *testing.T) {
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	const sec = "status-secret"

	sess, err := session.NewFromLogin(nil, &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rt",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
		Discovery: protocol.Discovery{TokenEndpoint: "https://auth.x.ai/oauth2/token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: (&server.Server{Session: sess, Secret: sec}).Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		server.RemoveUnixSocket(sock)
	})

	if err := waitDaemonReady(sock, sec, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// Wrong secret must not succeed.
	if err := waitDaemonReady(sock, "wrong", 300*time.Millisecond); err == nil {
		t.Fatal("expected fail with wrong secret")
	}
}

func mkdirShort(t *testing.T) (string, error) {
	t.Helper()
	// Prefer /tmp for short AF_UNIX paths (macOS sun_path limit).
	dir, err := os.MkdirTemp("/tmp", "xo-")
	if err != nil {
		dir, err = os.MkdirTemp("", "xo-")
		if err != nil {
			return "", err
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir, nil
}
