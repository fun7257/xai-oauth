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
	"net"
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
type loginHandoff struct {
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

	sec := strings.TrimSpace(*secret)
	generated := false
	var err error
	if sec == "" {
		if *fromLogin {
			return fmt.Errorf("empty --secret (daemon child requires secret)")
		}
		sec, err = randomSecret()
		if err != nil {
			return err
		}
		generated = true
	}

	// Background child: session from stdin, then serve until signal/logout.
	if *fromLogin {
		sess, err := sessionFromHandoff(os.Stdin)
		if err != nil {
			return err
		}
		return runServer(sockPath, sec, sess)
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

	printServeReady(sockPath, sec, generated)

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

	pid, err := spawnBackgroundDaemon(sockPath, sec, handoff)
	zeroHandoff(handoff)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Daemon running in background (pid %d). Terminal is free.\n", pid)
	fmt.Fprintln(os.Stderr, "  xai-oauth status | token | logout")
	return nil
}

func printServeReady(sockPath, sec string, generated bool) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Login successful. Serving local token API over Unix socket.")
	fmt.Fprintf(os.Stderr, "  socket:  %s\n", sockPath)
	if generated {
		fmt.Fprintf(os.Stderr, "  secret:  %s\n", sec)
		fmt.Fprintln(os.Stderr, "  (save this secret; it is not stored on disk)")
		fmt.Fprintln(os.Stderr, "  export XAI_OAUTH_SECRET='…'")
	} else {
		fmt.Fprintln(os.Stderr, "  secret:  (from --secret or XAI_OAUTH_SECRET)")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintf(os.Stderr, "  export XAI_OAUTH_SOCKET=%q\n", sockPath)
	fmt.Fprintln(os.Stderr, "  xai-oauth status")
	fmt.Fprintln(os.Stderr, "  xai-oauth token")
	fmt.Fprintln(os.Stderr, "  xai-oauth logout")
	fmt.Fprintln(os.Stderr)
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
// the login handoff from stdin and serves on the Unix socket.
func spawnBackgroundDaemon(sockPath, sec string, h *loginHandoff) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}

	cmd := exec.Command(exe, "serve",
		"--from-login",
		"--socket", sockPath,
		"--secret", sec,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
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
	if err := cmd.Process.Release(); err != nil {
		// Process is still running; Release failure is non-fatal on some platforms.
		_ = err
	}
	return pid, nil
}

func waitDaemonReady(sockPath, sec string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		// Prefer a real client Health; also accept bare dial if client init fails.
		c, err := client.New(client.Config{SocketPath: sockPath, Secret: sec})
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			hErr := c.Health(ctx)
			cancel()
			if hErr == nil {
				return nil
			}
			last = hErr
		} else {
			last = err
		}
		// Fallback: socket exists and accepts connections.
		conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err
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

func sessionFromHandoff(r io.Reader) (*session.Session, error) {
	var h loginHandoff
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("read login handoff: %w", err)
	}
	sess, err := session.NewFromLogin(protocol.NewIDPClient(protocol.IDPRequestTimeout), handoffToLoginResult(&h))
	zeroHandoff(&h)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func zeroHandoff(h *loginHandoff) {
	if h == nil {
		return
	}
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
