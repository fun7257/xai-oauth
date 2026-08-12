# Agent notes

## Cursor Cloud specific instructions

### Product

`xai-oauth` is a single Go CLI/daemon (not a monorepo). It performs xAI device-code OAuth once, keeps the session **in memory**, and serves `access_token` over a **Unix domain socket** HTTP control plane. There is no database, Redis, Docker Compose stack, or Node frontend.

### Toolchain

- Requires **Go 1.26+** (`go.mod`). Install the official toolchain under `/usr/local/go` if the distro `go` is older; put `/usr/local/go/bin` on `PATH` (also `$HOME/go/bin` for `go install` tools).
- No third-party Go module deps today; `go mod download` is a no-op but confirms the toolchain.

### Standard commands

See root `Makefile` / `README.md` Development section:

- Lint/static: `make fmt-check`, `make vet` (or `make check` for fmt + vet + test)
- Test: `make test`, `make test-race`
- Build/run: `make build` → `./xai-oauth`; then `./xai-oauth serve` / `status` / `token` / `logout`

### Runtime gotchas

- **Socket parent dir must be chmod-able to `0700`.** Binding under bare `/tmp/...sock` fails with `chmod /tmp: operation not permitted`. Use a subdirectory (e.g. `/tmp/xo-demo/daemon.sock`), `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock`, or the default `~/.xai-oauth/daemon.sock`.
- Socket mode is `0600`; local API secret is **env-only** (`XAI_OAUTH_SECRET`), never a CLI flag.
- Live `serve` talks to `https://auth.x.ai` (device code + refresh). Completing login needs a real SuperGrok / X Premium+ (or equivalent) account in a browser (`--no-browser` prints URL + code). Automated tests mock tokens and do **not** need IdP credentials.
- After `logout`, the daemon exits and the session is gone; run `serve` again to reauth. Tokens do not survive process restart.
- Control plane is Unix-domain only (Linux/macOS); no TCP/Windows support.

### Hello-world without IdP (control plane)

For a local smoke of status/token/logout without browser login, pipe a handoff JSON into the internal flag:

```bash
make build
mkdir -p /tmp/xo-demo
printf '%s' '{"secret":"demo","access_token":"at","refresh_token":"rt","token_endpoint":"https://auth.x.ai/oauth2/token","expires_in":3600}' \
  | ./xai-oauth serve --from-login --foreground --socket /tmp/xo-demo/daemon.sock
# other terminal:
export XAI_OAUTH_SECRET=demo XAI_OAUTH_SOCKET=/tmp/xo-demo/daemon.sock
./xai-oauth status && ./xai-oauth token && ./xai-oauth logout
```
