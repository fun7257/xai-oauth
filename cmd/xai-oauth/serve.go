//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fun7257/xai-oauth/client"
	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/server"
	"github.com/fun7257/xai-oauth/internal/session"
)

// loginHandoff is the stdin JSON payload from the interactive parent to the
// background daemon child (memory handoff only; never written to disk).
// Secret is included so the child need not take --secret on argv.
type loginHandoff struct {
	Secret        string `json:"secret"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	TokenEndpoint string `json:"token_endpoint"`
	ExpiresIn     int    `json:"expires_in"`
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", defaultSocket(), "unix socket path (env XAI_OAUTH_SOCKET)")
	secret := fs.String("secret", os.Getenv(client.EnvSecret), "local API secret (generated if empty)")
	noBrowser := fs.Bool("no-browser", false, "do not open the system browser for device login")
	foreground := fs.Bool("foreground", false, "stay attached to the terminal after login (do not background)")
	fromLogin := fs.Bool("from-login", false, "internal: read login handoff from stdin and serve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	sockPath := strings.TrimSpace(*socket)
	if sockPath == "" {
		return fmt.Errorf("empty --socket path")
	}

	// Background child: secret + session from stdin only (no --secret on argv).
	if *fromLogin {
		sess, sec, err := sessionFromHandoff(os.Stdin)
		if err != nil {
			return err
		}
		return runServer(sockPath, sec, sess)
	}

	sec := strings.TrimSpace(*secret)
	generated := false
	var err error
	if sec == "" {
		sec, err = randomSecret()
		if err != nil {
			return err
		}
		generated = true
	}

	// Avoid orphaning a previous daemon / stealing the socket after login.
	if err := refuseIfSocketBusy(sockPath, sec); err != nil {
		return err
	}

	httpClient := protocol.NewIDPClient(protocol.IDPRequestTimeout)

	fmt.Fprintln(os.Stderr, "xai-oauth serve — xAI OAuth2 personal (device login)")
	fmt.Fprintf(os.Stderr, "  scope:  %s\n", protocol.Scope)
	fmt.Fprintln(os.Stderr)

	loginCtx, loginCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer loginCancel()

	handoff, err := deviceLoginHandoff(loginCtx, httpClient, !*noBrowser)
	if err != nil {
		return err
	}
	handoff.Secret = sec

	// Credentials after login; do not claim "serving" until listen/ready succeeds.
	printLoginCredentials(sockPath, sec, generated)

	if *foreground {
		sess, err := session.NewFromLogin(httpClient, handoffToLoginResult(handoff))
		zeroHandoff(handoff)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Running in foreground (--foreground). Ctrl-C to stop.")
		fmt.Fprintln(os.Stderr)
		return runServer(sockPath, sec, sess)
	}

	pid, err := spawnBackgroundDaemon(sockPath, handoff)
	zeroHandoff(handoff)
	if err != nil {
		return fmt.Errorf("daemon failed to start (tokens not retained in this process): %w", err)
	}
	fmt.Fprintf(os.Stderr, "Daemon running in background (pid %d). Terminal is free.\n", pid)
	fmt.Fprintln(os.Stderr, "  xai-oauth status | token | logout")
	return nil
}

func printLoginCredentials(sockPath, sec string, generated bool) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Login successful.")
	fmt.Fprintf(os.Stderr, "  socket:  %s\n", sockPath)
	if generated {
		fmt.Fprintf(os.Stderr, "  secret:  %s\n", sec)
		fmt.Fprintln(os.Stderr, "  (save this secret; it is not stored on disk)")
		fmt.Fprintln(os.Stderr, "  export XAI_OAUTH_SECRET='…'")
	} else {
		fmt.Fprintln(os.Stderr, "  secret:  (from --secret or XAI_OAUTH_SECRET)")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands (after daemon is up):")
	fmt.Fprintf(os.Stderr, "  export XAI_OAUTH_SOCKET=%q\n", sockPath)
	fmt.Fprintln(os.Stderr, "  xai-oauth status")
	fmt.Fprintln(os.Stderr, "  xai-oauth token")
	fmt.Fprintln(os.Stderr, "  xai-oauth logout")
	fmt.Fprintln(os.Stderr)
}

// refuseIfSocketBusy fails if something already answers on the socket, so a
// second serve cannot orphan a previous token-holding process.
func refuseIfSocketBusy(sockPath, sec string) error {
	c, err := client.New(client.Config{SocketPath: sockPath, Secret: sec})
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := c.Health(ctx); err != nil {
		return nil
	}
	if st, err := c.Status(ctx); err == nil && st != nil {
		return fmt.Errorf("daemon already running on %s (state=%s); run: xai-oauth logout", sockPath, st.State)
	}
	return fmt.Errorf("socket %s is already in use (wrong secret or foreign listener); logout or free the path", sockPath)
}

func runServer(sockPath, sec string, sess *session.Session) error {
	ln, err := server.ListenUnix(sockPath)
	if err != nil {
		return err
	}
	defer server.RemoveUnixSocket(sockPath)

	const (
		readHeader = 10 * time.Second
		readBody   = 10 * time.Second
		writeWait  = protocol.IDPRequestTimeout + 10*time.Second
		idle       = 60 * time.Second
	)

	shutdownCh := make(chan struct{}, 1)
	srv := &server.Server{
		Session: sess,
		Secret:  sec,
		OnLogout: func() {
			select {
			case shutdownCh <- struct{}{}:
			default:
			}
		},
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: readHeader,
		ReadTimeout:       readHeader + readBody,
		WriteTimeout:      writeWait,
		IdleTimeout:       idle,
		MaxHeaderBytes:    1 << 14,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Fprintf(os.Stderr, "signal %v, shutting down\n", sig)
	case <-shutdownCh:
		fmt.Fprintln(os.Stderr, "logout requested, shutting down")
	case err := <-errCh:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	return nil
}

// spawnBackgroundDaemon re-execs this binary as a detached child that reads
// the login handoff (including secret) from stdin and serves on the Unix socket.
func spawnBackgroundDaemon(sockPath string, h *loginHandoff) (int, error) {
	if h == nil || strings.TrimSpace(h.Secret) == "" {
		return 0, fmt.Errorf("login handoff missing secret")
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	// No --secret on argv: secret travels only in the stdin handoff.
	cmd := exec.Command(exe, "serve",
		"--from-login",
		"--socket", sockPath,
	)
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, fmt.Errorf("daemon stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}
	pid := cmd.Process.Pid
	sec := h.Secret

	enc := json.NewEncoder(stdin)
	if err := enc.Encode(h); err != nil {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("write login handoff: %w", err)
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("close login handoff: %w", err)
	}

	if err := waitDaemonReady(sockPath, sec, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, err
	}

	// Detach: do not wait for the daemon; it outlives this CLI.
	_ = cmd.Process.Release()
	return pid, nil
}

// waitDaemonReady requires a secret-authenticated GET /status with state ready.
// Unauthenticated /health or a bare dial is not enough (avoids false ready on
// a pre-existing foreign or old daemon).
func waitDaemonReady(sockPath, sec string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		c, err := client.New(client.Config{SocketPath: sockPath, Secret: sec})
		if err != nil {
			last = err
			time.Sleep(30 * time.Millisecond)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		st, err := c.Status(ctx)
		cancel()
		if err == nil && st != nil && st.State == string(session.StateReady) {
			return nil
		}
		if err != nil {
			last = err
		} else if st != nil {
			last = fmt.Errorf("daemon state %q", st.State)
		} else {
			last = fmt.Errorf("empty status")
		}
		time.Sleep(30 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return fmt.Errorf("daemon did not become ready: %w", last)
}

func deviceLoginHandoff(ctx context.Context, httpClient *http.Client, openBrowser bool) (*loginHandoff, error) {
	result, err := protocol.DeviceLogin(ctx, httpClient, openBrowser, func(s string) {
		fmt.Fprintln(os.Stderr, s)
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	h := &loginHandoff{
		AccessToken:   result.Tokens.AccessToken,
		RefreshToken:  result.Tokens.RefreshToken,
		TokenEndpoint: result.Discovery.TokenEndpoint,
		ExpiresIn:     result.Tokens.ExpiresIn,
	}
	// Drop OAuth material from the login result immediately.
	result.Tokens = protocol.TokenResponse{}
	if h.AccessToken == "" || h.RefreshToken == "" {
		return nil, fmt.Errorf("login: missing access or refresh token")
	}
	if err := protocol.ValidateXAIURL(h.TokenEndpoint, "token_endpoint"); err != nil {
		return nil, err
	}
	return h, nil
}

func handoffToLoginResult(h *loginHandoff) *protocol.LoginResult {
	return &protocol.LoginResult{
		Tokens: protocol.TokenResponse{
			AccessToken:  h.AccessToken,
			RefreshToken: h.RefreshToken,
			ExpiresIn:    h.ExpiresIn,
			TokenType:    "Bearer",
		},
		Discovery: protocol.Discovery{TokenEndpoint: h.TokenEndpoint},
	}
}

// sessionFromHandoff reads secret + tokens from r. Secret is returned separately
// so it is not left only inside the zeroed handoff struct.
func sessionFromHandoff(r io.Reader) (*session.Session, string, error) {
	var h loginHandoff
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	if err := dec.Decode(&h); err != nil {
		return nil, "", fmt.Errorf("read login handoff: %w", err)
	}
	sec := strings.TrimSpace(h.Secret)
	if sec == "" {
		zeroHandoff(&h)
		return nil, "", fmt.Errorf("login handoff missing secret")
	}
	sess, err := session.NewFromLogin(protocol.NewIDPClient(protocol.IDPRequestTimeout), handoffToLoginResult(&h))
	zeroHandoff(&h)
	if err != nil {
		return nil, "", err
	}
	return sess, sec, nil
}

func zeroHandoff(h *loginHandoff) {
	if h == nil {
		return
	}
	h.Secret = ""
	h.AccessToken = ""
	h.RefreshToken = ""
	h.TokenEndpoint = ""
	h.ExpiresIn = 0
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
