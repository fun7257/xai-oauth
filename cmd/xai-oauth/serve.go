package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fun7257/xai-oauth/client"
	"github.com/fun7257/xai-oauth/internal/protocol"
	"github.com/fun7257/xai-oauth/internal/server"
	"github.com/fun7257/xai-oauth/internal/session"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", defaultSocket(), "unix socket path (env XAI_OAUTH_SOCKET)")
	secret := fs.String("secret", os.Getenv(client.EnvSecret), "local API secret (generated if empty)")
	noBrowser := fs.Bool("no-browser", false, "do not open the system browser for device login")
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
		sec, err = randomSecret()
		if err != nil {
			return err
		}
		generated = true
	}

	httpClient := protocol.NewIDPClient(protocol.IDPRequestTimeout)

	fmt.Fprintln(os.Stderr, "xai-oauth serve — xAI OAuth2 personal (device login)")
	fmt.Fprintf(os.Stderr, "  scope:  %s\n", protocol.Scope)
	fmt.Fprintln(os.Stderr)

	loginCtx, loginCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer loginCancel()

	sess, err := loginSession(loginCtx, httpClient, !*noBrowser)
	if err != nil {
		return err
	}

	ln, err := server.ListenUnix(sockPath)
	if err != nil {
		return err
	}
	defer server.RemoveUnixSocket(sockPath)

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
	fmt.Fprintln(os.Stderr, "Commands (another terminal):")
	fmt.Fprintf(os.Stderr, "  export XAI_OAUTH_SOCKET=%q\n", sockPath)
	fmt.Fprintln(os.Stderr, "  xai-oauth status")
	fmt.Fprintln(os.Stderr, "  xai-oauth token")
	fmt.Fprintln(os.Stderr, "  xai-oauth logout")
	fmt.Fprintln(os.Stderr)

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

// loginSession runs device login and returns a Session as the sole credential
// holder. LoginResult token fields are zeroed before return so Clear/logout
// cannot leave a second copy in the serve stack frame.
func loginSession(ctx context.Context, httpClient *http.Client, openBrowser bool) (*session.Session, error) {
	result, err := protocol.DeviceLogin(ctx, httpClient, openBrowser, func(s string) {
		fmt.Fprintln(os.Stderr, s)
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	sess, err := session.NewFromLogin(httpClient, result)
	// Drop OAuth material from the login result regardless of NewFromLogin outcome.
	result.Tokens = protocol.TokenResponse{}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
