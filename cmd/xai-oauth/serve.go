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
// Secret is included so the child need not read env or flags.
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

	// Background child: secret + session from stdin only (never CLI flags).
	if *fromLogin {
		sess, sec, err := sessionFromHandoff(os.Stdin)
		if err != nil {
			return err
		}
		return runServer(sockPath, sec, sess)
	}

	// Operator secret: environment only (no --secret flag).
	sec := strings.TrimSpace(os.Getenv(client.EnvSecret))
	generated := false

	// Converge to a healthy daemon: take over a running one (session
	// preserved, no re-login), replace one whose session is sticky-dead
	// (fresh login), refuse when we cannot authenticate to it.
	var handoff *loginHandoff
	replaceDead := false
	if daemonAlive(sockPath) {
		if sec == "" {
			return fmt.Errorf("daemon already running on %s but XAI_OAUTH_SECRET is not set; export the daemon's secret, or run: xai-oauth logout", sockPath)
		}
		outcome, h, err := attemptHandoff(sockPath, sec)
		if err != nil {
			return err
		}
		switch outcome {
		case takeoverAcquired:
			handoff = h
			handoff.Secret = sec
			fmt.Fprintln(os.Stderr, "xai-oauth serve — taking over the running daemon (no re-login)")
		case takeoverDeadSession:
			replaceDead = true
			fmt.Fprintln(os.Stderr, "xai-oauth serve — running daemon has a dead session; signing in, then replacing it")
		}
	} else if sec == "" {
		var err error
		sec, err = randomSecret()
		if err != nil {
			return err
		}
		generated = true
	}

	httpClient := protocol.NewIDPClient(protocol.IDPRequestTimeout)

	if handoff == nil {
		fmt.Fprintln(os.Stderr, "xai-oauth serve — xAI OAuth2 personal (device login)")
		fmt.Fprintf(os.Stderr, "  scope:  %s\n", protocol.Scope)
		fmt.Fprintln(os.Stderr)

		loginCtx, loginCancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer loginCancel()

		h, err := deviceLoginHandoff(loginCtx, httpClient, !*noBrowser)
		if err != nil {
			return err
		}
		handoff = h
		handoff.Secret = sec

		if replaceDead {
			// Sticky states already wiped the old daemon's tokens; stopping
			// it loses nothing. Stop it only after the login succeeded so a
			// failed login leaves the (still inspectable) daemon in place.
			if err := logoutOldDaemon(sockPath, sec); err != nil {
				zeroHandoff(handoff)
				return fmt.Errorf("login succeeded but the previous daemon would not stop: %w", err)
			}
		}

		// Credentials after login; do not claim "serving" until listen/ready succeeds.
		printLoginCredentials(sockPath, sec, generated)
	} else {
		printTakeover(sockPath)
	}

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
		fmt.Fprintln(os.Stderr, "  secret:  (from env XAI_OAUTH_SECRET)")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands (after daemon is up):")
	fmt.Fprintf(os.Stderr, "  export XAI_OAUTH_SOCKET=%q\n", sockPath)
	fmt.Fprintln(os.Stderr, "  xai-oauth status")
	fmt.Fprintln(os.Stderr, "  xai-oauth token")
	fmt.Fprintln(os.Stderr, "  xai-oauth logout")
	fmt.Fprintln(os.Stderr)
}

func printTakeover(sockPath string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Session taken over from the previous daemon — no re-login needed.")
	fmt.Fprintf(os.Stderr, "  socket:  %s\n", sockPath)
	fmt.Fprintln(os.Stderr, "  secret:  (unchanged, from env XAI_OAUTH_SECRET)")
	fmt.Fprintln(os.Stderr)
}

// withSecretEnv temporarily sets XAI_OAUTH_SECRET so client.New (env-only)
// can authenticate. Used when serve generated a secret not yet exported.
func withSecretEnv(sec string, fn func() error) error {
	prev, had := os.LookupEnv(client.EnvSecret)
	if err := os.Setenv(client.EnvSecret, sec); err != nil {
		return err
	}
	defer func() {
		if had {
			_ = os.Setenv(client.EnvSecret, prev)
		} else {
			_ = os.Unsetenv(client.EnvSecret)
		}
	}()
	return fn()
}

func runServer(sockPath, sec string, sess *session.Session) error {
	// Retry through a predecessor's shutdown window (takeover/replace);
	// non-busy errors fail immediately.
	ln, err := listenWithRetry(sockPath, 5*time.Second)
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

	// Secret travels only in the stdin handoff (not env, not argv):
	// strip XAI_OAUTH_SECRET from the inherited environment so it does not
	// linger in the daemon's /proc/<pid>/environ.
	cmd := exec.Command(exe, "serve",
		"--from-login",
		"--socket", sockPath,
	)
	cmd.Env = daemonEnv(os.Environ())
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = daemonSysProcAttr()

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

// waitDaemonReady requires a secret-authenticated GET /status with state ready
// (client.WaitReady). Unauthenticated /health or a bare dial is not enough
// (avoids false ready on a pre-existing foreign or old daemon); a rejected
// secret or sticky reauth/tier state fails fast instead of polling out.
func waitDaemonReady(sockPath, sec string, timeout time.Duration) error {
	return withSecretEnv(sec, func() error {
		c, err := client.New(client.Config{SocketPath: sockPath})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := c.WaitReady(ctx); err != nil {
			return fmt.Errorf("daemon did not become ready: %w", err)
		}
		return nil
	})
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

// daemonEnv returns environ minus XAI_OAUTH_SECRET entries. The daemon child
// receives the secret via the stdin handoff only; everything else (PATH, HOME,
// proxy variables for IdP egress, …) is inherited unchanged.
func daemonEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	prefix := client.EnvSecret + "="
	for _, kv := range environ {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// zeroHandoff drops references to handoff credentials as early as possible.
// Best-effort only: Go strings are immutable, so copies (including encoder
// buffers) may persist on the heap until garbage collection. This limits
// accidental reuse; it is not a guaranteed memory wipe (see SECURITY.md).
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
