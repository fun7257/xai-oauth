package client_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fun7257/xai-oauth/client"
	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/server"
	"github.com/fun7257/xai-oauth/internal/session"
)

// End-to-end: real ListenUnix + Server.Handler + client over UDS (shipped path).
func TestClientOverUnixSocket_E2E(t *testing.T) {
	// Short path: macOS AF_UNIX sun_path is ~104 bytes. Fall back to the OS
	// temp dir where /tmp does not exist (Windows).
	dir, err := os.MkdirTemp("/tmp", "xo-")
	if err != nil {
		dir, err = os.MkdirTemp("", "xo-")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	const secret = "e2e-secret"
	t.Setenv(client.EnvSecret, secret)

	sess, err := session.NewFromLogin(nil, &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  "e2e-access-token",
			RefreshToken: "e2e-refresh",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		},
		Discovery: protocol.Discovery{
			TokenEndpoint: "https://auth.x.ai/oauth2/token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := server.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		server.RemoveUnixSocket(sock)
	})

	httpSrv := &http.Server{Handler: (&server.Server{Session: sess, Secret: secret}).Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	})

	c, err := client.New(client.Config{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath() != sock {
		t.Fatalf("SocketPath = %q", c.SocketPath())
	}

	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	ready, state, err := c.Ready(ctx)
	if err != nil || !ready {
		t.Fatalf("ready=%v state=%s err=%v", ready, state, err)
	}
	tok, err := c.Get(ctx)
	if err != nil || tok != "e2e-access-token" {
		t.Fatalf("token=%q err=%v", tok, err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.State != "ready" {
		t.Fatalf("status=%+v err=%v", st, err)
	}
}
