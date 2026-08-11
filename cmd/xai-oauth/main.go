package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "xai-oauth: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return fmt.Errorf("missing command (try: serve | status | token | logout | version)")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest)
	case "status":
		return cmdStatus(rest)
	case "token":
		return cmdToken(rest)
	case "logout":
		return cmdLogout(rest)
	case "version", "-version", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `xai-oauth — local xAI OAuth2 personal token daemon (Unix socket + HTTP)

Usage:
  xai-oauth serve   [flags]   device login then serve on a Unix socket
  xai-oauth status  [flags]   query running daemon (requires secret)
  xai-oauth token   [flags]   print access_token (requires secret)
  xai-oauth logout  [flags]   clear session and stop daemon (requires secret)
  xai-oauth version

Credentials live only in the serve process (memory). Control commands talk to
that process over HTTP-on-Unix-socket. Restart serve after logout/reauth.

Flags (per command):
  --socket  path (default: $XDG_RUNTIME_DIR/…, else ~/.xai-oauth/…, else $TMPDIR/…)
            env: XAI_OAUTH_SOCKET
  --secret  local API secret (env XAI_OAUTH_SECRET; serve generates if empty;
            required for status/token/logout)
  --no-browser   serve: do not open the device-login browser (default: try open)

SDK: github.com/fun7257/xai-oauth/client
  c, _ := client.New(client.Config{Secret: "..."})
  tok, _ := c.Get(ctx)
`)
}
