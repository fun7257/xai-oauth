package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fun7257/xai-oauth/client"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func defaultSocket() string {
	if p := strings.TrimSpace(os.Getenv(client.EnvSocket)); p != "" {
		return p
	}
	return client.DefaultSocketPath()
}

type commonFlags struct {
	fs     *flag.FlagSet
	socket *string
	secret *string
}

func newCommonFlags(name string) *commonFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := &commonFlags{fs: fs}
	c.socket = fs.String("socket", defaultSocket(), "unix socket path (env XAI_OAUTH_SOCKET)")
	c.secret = fs.String("secret", os.Getenv(client.EnvSecret), "local API secret")
	return c
}

func (c *commonFlags) parse(args []string) error {
	if err := c.fs.Parse(args); err != nil {
		return err
	}
	if c.fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", c.fs.Args())
	}
	return nil
}
