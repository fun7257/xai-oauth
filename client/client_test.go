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

// shortTempDir keeps AF_UNIX paths short (macOS sun_path ~104 bytes).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xo-")
	if err != nil {
		dir, err = os.MkdirTemp("", "xo-")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startUnixDaemon(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "s.sock")
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
	return sock
}

func TestGetTokenOK(t *testing.T) {
	t.Setenv(EnvSecret, "test-secret")
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
	sock := startUnixDaemon(t, mux)

	c, err := New(Config{SocketPath: sock})
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
	t.Setenv(EnvSecret, "s")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "reauth_required",
			"message": "restart",
		})
	})
	sock := startUnixDaemon(t, mux)

	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestGetUnauthorized(t *testing.T) {
	t.Setenv(EnvSecret, "wrong")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})
	sock := startUnixDaemon(t, mux)

	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewRequiresSecretEnv(t *testing.T) {
	t.Setenv(EnvSecret, "")
	_, err := New(Config{SocketPath: "/tmp/x.sock"})
	if err == nil {
		t.Fatal("expected secret required")
	}
}

func TestGetUnreachableSentinel(t *testing.T) {
	t.Setenv(EnvSecret, "s")
	sock := filepath.Join(shortTempDir(t), "absent.sock")
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if err := c.Health(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("health err = %v, want ErrUnreachable", err)
	}
}

func TestStatusLogoutReadyHealth(t *testing.T) {
	t.Setenv(EnvSecret, "s")
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
	sock := startUnixDaemon(t, mux)

	c, err := New(Config{SocketPath: sock})
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
	if err != nil || st.State != StateReady {
		t.Fatalf("status %+v err=%v", st, err)
	}
	if !st.HasExpiry || st.ExpiresAt.Year() != 2099 {
		t.Fatalf("expires_at not parsed: %+v", st)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if !loggedOut {
		t.Fatal("logout not hit")
	}
}
