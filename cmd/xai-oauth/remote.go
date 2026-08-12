package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fun7257/xai-oauth/client"
)

// requireSecret reads XAI_OAUTH_SECRET only (no CLI flag; avoids argv leakage).
func requireSecret() (string, error) {
	secret := strings.TrimSpace(os.Getenv(client.EnvSecret))
	if secret == "" {
		return "", fmt.Errorf("secret is required (set env %s)", client.EnvSecret)
	}
	return secret, nil
}

func daemonClient(socket string) (*client.Client, error) {
	// Secret comes only from XAI_OAUTH_SECRET (see client.New).
	return client.New(client.Config{
		SocketPath: strings.TrimSpace(socket),
	})
}

func cmdStatus(args []string) error {
	cf := newCommonFlags("status")
	if err := cf.parse(args); err != nil {
		return err
	}
	if _, err := requireSecret(); err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket)
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
	if _, err := requireSecret(); err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket)
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
	if _, err := requireSecret(); err != nil {
		return err
	}
	c, err := daemonClient(*cf.socket)
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
