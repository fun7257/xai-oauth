package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func statusDaemon(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", handler)
	return startUnixDaemon(t, mux)
}

func TestWaitReadyImmediate(t *testing.T) {
	t.Setenv(EnvSecret, "s")
	sock := statusDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "ready"})
	})
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReadyPollsUntilReady(t *testing.T) {
	t.Setenv(EnvSecret, "s")
	var n int
	sock := statusDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		n++
		state := "ready"
		if n < 3 {
			state = "degraded" // transient: keep polling
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"state": state})
	})
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("status polls = %d, want >= 3", n)
	}
}

func TestWaitReadyFailsFastOnStickyStates(t *testing.T) {
	cases := []struct {
		state string
		want  error
	}{
		{state: "reauth_required", want: ErrReauthRequired},
		{state: "tier_denied", want: ErrTierDenied},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			t.Setenv(EnvSecret, "s")
			sock := statusDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"state": tc.state})
			})
			c, err := New(Config{SocketPath: sock})
			if err != nil {
				t.Fatal(err)
			}
			// Generous ctx: fail-fast must not consume it.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			err = c.WaitReady(ctx)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatalf("sticky state should fail fast, took %v", time.Since(start))
			}
		})
	}
}

func TestWaitReadyFailsFastOnBadSecret(t *testing.T) {
	t.Setenv(EnvSecret, "wrong")
	sock := statusDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestWaitReadyUnreachableTimesOut(t *testing.T) {
	t.Setenv(EnvSecret, "s")
	sock := filepath.Join(shortTempDir(t), "absent.sock")
	c, err := New(Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = c.WaitReady(ctx)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable in chain", err)
	}
}
