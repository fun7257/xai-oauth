package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func startUnixDaemon(t *testing.T, secret string, mux *http.ServeMux) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "daemon.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(sock)
	})
	_ = secret
	return sock
}

func TestGetTokenOK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "at-123",
			"token_type":   "Bearer",
		})
	})
	sock := startUnixDaemon(t, "test-secret", mux)

	c, err := New(Config{SocketPath: sock, Secret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath() != sock {
		t.Fatalf("socket %q", c.SocketPath())
	}
	tok, err := c.Get(context.Background())
	if err != nil || tok != "at-123" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
}

func TestGetReauth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "reauth_required",
			"message": "restart",
		})
	})
	sock := startUnixDaemon(t, "s", mux)

	c, err := New(Config{SocketPath: sock, Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestGetUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})
	sock := startUnixDaemon(t, "right", mux)

	c, err := New(Config{SocketPath: sock, Secret: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewRequiresSecret(t *testing.T) {
	t.Setenv(EnvSecret, "")
	_, err := New(Config{SocketPath: "/tmp/x.sock"})
	if err == nil {
		t.Fatal("expected secret required")
	}
}

func TestDefaultSocketPath(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	p := DefaultSocketPath()
	if p != "/run/user/1000/xai-oauth/daemon.sock" {
		t.Fatalf("got %q", p)
	}
}

func TestStatusLogoutReadyHealth(t *testing.T) {
	var loggedOut bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Fatal("expected Authorization on health")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state":      "ready",
			"has_expiry": true,
			"expires_at": "2099-01-01T00:00:00Z",
		})
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		loggedOut = true
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	sock := startUnixDaemon(t, "s", mux)

	c, err := New(Config{SocketPath: sock, Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	ok, state, err := c.Ready(ctx)
	if err != nil || !ok || state != "ready" {
		t.Fatalf("ready ok=%v state=%s err=%v", ok, state, err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.State != "ready" {
		t.Fatalf("status %+v err=%v", st, err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if !loggedOut {
		t.Fatal("logout not hit")
	}
}
