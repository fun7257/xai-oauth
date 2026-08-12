package main

import (
	"errors"
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

// startDaemon serves a real Server (ready session) on a fresh unix socket.
func startDaemon(t *testing.T, sess *session.Session, secret string) (sock string, shutdown chan struct{}) {
	t.Helper()
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "s.sock")
	ln, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	shutdown = make(chan struct{}, 1)
	srv := &http.Server{Handler: (&server.Server{
		Session:  sess,
		Secret:   secret,
		OnLogout: func() { shutdown <- struct{}{} },
	}).Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		server.RemoveUnixSocket(sock)
	})
	return sock, shutdown
}

func newReadySession(t *testing.T) *session.Session {
	t.Helper()
	sess, err := session.NewFromLogin(nil, &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  "live-at",
			RefreshToken: "live-rt",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
		Discovery: protocol.Discovery{TokenEndpoint: "https://auth.x.ai/oauth2/token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestAttemptHandoffAcquires(t *testing.T) {
	const secret = "tk-secret"
	sock, shutdown := startDaemon(t, newReadySession(t), secret)

	if !daemonAlive(sock) {
		t.Fatal("daemon should be alive")
	}
	outcome, h, err := attemptHandoff(sock, secret)
	if err != nil || outcome != takeoverAcquired {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if h.AccessToken != "live-at" || h.RefreshToken != "live-rt" {
		t.Fatalf("handoff %+v", h)
	}
	if h.ExpiresIn <= 0 || h.ExpiresIn > 3600 {
		t.Fatalf("expires_in = %d, want (0,3600]", h.ExpiresIn)
	}
	if !strings.HasPrefix(h.TokenEndpoint, "https://auth.x.ai/") {
		t.Fatalf("endpoint %q", h.TokenEndpoint)
	}
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("old daemon did not begin shutdown")
	}
}

func TestAttemptHandoffWrongSecret(t *testing.T) {
	sock, _ := startDaemon(t, newReadySession(t), "right")
	_, _, err := attemptHandoff(sock, "wrong")
	if err == nil || !strings.Contains(err.Error(), "wrong secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestAttemptHandoffDeadSession(t *testing.T) {
	const secret = "tk"
	sess := newReadySession(t)
	sess.Clear() // sticky reauth_required
	sock, _ := startDaemon(t, sess, secret)

	outcome, h, err := attemptHandoff(sock, secret)
	if err != nil || outcome != takeoverDeadSession || h != nil {
		t.Fatalf("outcome=%v h=%v err=%v", outcome, h, err)
	}
}

func TestAttemptHandoffUnsupportedDaemon(t *testing.T) {
	// A pre-takeover daemon has no /handoff route: mux returns 404.
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	ln, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		server.RemoveUnixSocket(sock)
	})

	_, _, err = attemptHandoff(sock, "s")
	if err == nil || !strings.Contains(err.Error(), "predates session takeover") {
		t.Fatalf("err = %v", err)
	}
}

func TestListenWithRetryWaitsForRelease(t *testing.T) {
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	old, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the old listener accepting so the liveness probe sees it, then
	// release it mid-retry.
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = old.Close()
		server.RemoveUnixSocket(sock)
	}()

	start := time.Now()
	ln, err := listenWithRetry(sock, 5*time.Second)
	if err != nil {
		t.Fatalf("listenWithRetry: %v", err)
	}
	defer func() {
		_ = ln.Close()
		server.RemoveUnixSocket(sock)
	}()
	if time.Since(start) < 250*time.Millisecond {
		t.Fatalf("bound too early (%v); expected to wait for release", time.Since(start))
	}
}

func TestListenWithRetryFailsFastOnNonBusyError(t *testing.T) {
	dir, err := mkdirShort(t)
	if err != nil {
		t.Fatal(err)
	}
	// Regular file at the socket path: not a busy socket → fail immediately.
	path := filepath.Join(dir, "notasock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = listenWithRetry(path, 5*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, server.ErrSocketInUse) {
		t.Fatalf("unexpected busy classification: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("non-busy error should fail fast, took %v", time.Since(start))
	}
}
