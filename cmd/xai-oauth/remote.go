package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fun7257/xai-oauth/client"
)

func requireSecret(flagSecret string) (string, error) {
	secret := strings.TrimSpace(flagSecret)
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv(client.EnvSecret))
	}
	if secret == "" {
		return "", fmt.Errorf("secret is required (--secret or %s)", client.EnvSecret)
	}
	return secret, nil
}

func daemonClient(socket, secret string) (*client.Client, error) {
	return client.New(client.Config{
		SocketPath: strings.TrimSpace(socket),
		Secret:     secret,
	})
}

func cmdStatus(args []string) error {
	cf := newCommonFlags("status")
	if err := cf.parse(args); err != nil {
		return err
	}
	secret, err := requireSecret(*cf.secret)
	if err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket, secret)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := c.Health(ctx); err != nil {
		fmt.Println("daemon: down")
		fmt.Fprintf(os.Stderr, "  socket: %s\n", c.SocketPath())
		fmt.Fprintf(os.Stderr, "  (%v)\n", err)
		return fmt.Errorf("daemon not reachable; start with: xai-oauth serve")
	}
	fmt.Println("daemon: up")
	fmt.Printf("socket: %s\n", c.SocketPath())

	ready, state, err := c.Ready(ctx)
	if err != nil {
		return err
	}
	if ready {
		fmt.Println("ready:  true")
	} else {
		fmt.Printf("ready:  false (%s)\n", state)
	}

	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("state:  %s\n", st.State)
	if st.HasExpiry && st.ExpiresAt != "" {
		fmt.Printf("expires_at: %s\n", st.ExpiresAt)
	}
	if st.LastError != "" {
		fmt.Printf("last_error: %s\n", st.LastError)
	}
	return nil
}

func cmdToken(args []string) error {
	cf := newCommonFlags("token")
	if err := cf.parse(args); err != nil {
		return err
	}
	secret, err := requireSecret(*cf.secret)
	if err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket, secret)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, err := c.Get(ctx)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdLogout(args []string) error {
	cf := newCommonFlags("logout")
	if err := cf.parse(args); err != nil {
		return err
	}
	secret, err := requireSecret(*cf.secret)
	if err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket, secret)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Logout(ctx); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "logged out; daemon is shutting down")
	return nil
}
