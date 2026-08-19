package main

import (
	"fmt"
	"os"
)

// version is overridden at link time via -X main.version=… (release tags).
var version = "dev"

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
  xai-oauth serve   [flags]   take over a running daemon (no re-login) or
                              device login, then daemonize (background by default)
  xai-oauth status  [flags]   query running daemon (needs XAI_OAUTH_SECRET)
  xai-oauth token   [flags]   print access_token (needs XAI_OAUTH_SECRET)
  xai-oauth logout  [flags]   clear session and stop daemon (needs XAI_OAUTH_SECRET)
  xai-oauth version

Credentials live only in the serve process (memory). After successful login,
serve detaches so the terminal is free. Control commands talk over
HTTP-on-Unix-socket. Restart serve after logout/reauth.

Local API secret is env-only: XAI_OAUTH_SECRET (no --secret flag).
serve generates one if unset and prints it once — export it for status/token/logout.
Operator-provided secrets must be at least 16 characters.

Flags (per command):
  --socket  path (default: $XDG_RUNTIME_DIR/…, else ~/.xai-oauth/…, else $TMPDIR/…;
            Windows: %%LOCALAPPDATA%%\xai-oauth\daemon.sock)
            env: XAI_OAUTH_SOCKET
  --no-browser   serve: do not open the device-login browser (default: try open)
  --foreground   serve: stay in the terminal after login (do not background)

SDK: github.com/fun7257/xai-oauth/client
  // export XAI_OAUTH_SECRET=…  (required; only source for secret)
  c, _ := client.New(client.Config{})
  tok, _ := c.Get(ctx)
`)
}
