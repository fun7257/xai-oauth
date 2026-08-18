# xai-oauth

**Local developer tool** — a single-operator OAuth sidecar for xAI (Grok).
It runs device-code login once, keeps the session **in memory**, and hands out
usable `access_token` values over a **Unix domain socket** (HTTP). Your apps
call `https://api.x.ai` themselves with that bearer.

> **Not affiliated with xAI.** Unofficial, community-maintained software.  
> **For your machine only** — not a multi-tenant or public token service.  
> License: [MIT](LICENSE). Security model: [SECURITY.md](SECURITY.md).  
> Design: [DESIGN.md](DESIGN.md). Reference: [docs/REFERENCE.md](docs/REFERENCE.md).  
> Chinese: [README_zh.md](README_zh.md).

## Important: security & scope

| Do | Don’t |
|----|--------|
| Keep the daemon on a **user-only Unix socket** (default `0600`) | Treat this as a shared or network service |
| Set **`XAI_OAUTH_SECRET`** in the environment (CLI has no `--secret` flag) | Put the secret on the command line or in world-readable scripts |
| Treat OAuth access/refresh tokens as secrets | Log full tokens or leave `token` stdout in world-readable CI logs |
| Rerun `serve` after logout / reauth — and to **upgrade in place** (running daemon's session is taken over, no re-login) | Expect tokens to survive a crash or reboot (memory only) |

Anyone who can open the socket **and** present the local secret can obtain
**your** OAuth access token and spend **your** API quota.

OAuth uses a **public** device-code client id (no app client secret). xAI may
change allowlists, scopes, or terms at any time; use at your own risk.

## Attribution

- Protocol layout (device code, refresh, host pinning) was developed **with
  reference to** [xai-proxy](https://github.com/fun7257/xai-proxy) and the same
  public device-client patterns discussed there (including community flow notes
  tracing to [Hermes Agent](https://github.com/NousResearch/hermes-agent)).
- Default OAuth **scopes** follow the personal defaults used by **grok-build** /
  Grok CLI-style clients (`grok-cli:access`, `api:access`, conversations/workspaces).
- This project is **independent** and is **not** affiliated with xAI, Hermes
  Agent, Nous Research, or any official Grok product.

## What this is for

- Local tools/scripts that need a live xAI bearer without managing refresh logic
- A small Go SDK (`client` package) that talks to a running `serve` process

## What this is not

- An official xAI product or supported integration
- A reverse proxy for `api.x.ai` (see **xai-proxy** for that)
- Disk-backed multi-account SSO or a team gateway

## Requirements

- Go **1.26+** (see `go.mod`)
- SuperGrok or X Premium+ (or whatever tier xAI requires for OAuth API access)
- **Linux, macOS, or Windows 10 1803+ / Server 2019+** (AF_UNIX sockets)

Control plane and SDK use Unix domain sockets (AF_UNIX) on every platform;
there is no Named Pipe / TCP fallback. On Windows, per-user isolation comes
from the NTFS ACLs of the default `%LOCALAPPDATA%\xai-oauth` directory
instead of POSIX file modes (see [SECURITY.md](SECURITY.md)).

## Install

From source (Go 1.26+):

```bash
cd xai-oauth
make build                 # → ./xai-oauth
# or: make install         # → ~/.local/bin/xai-oauth   (make uninstall to remove)
# or, without cloning:
go install github.com/fun7257/xai-oauth/cmd/xai-oauth@latest
```

Or download a release: tagged releases (`v*`) publish **Linux, macOS
(`.tar.gz`), and Windows (`.zip`)** binaries via GitHub Actions (see
[.github/workflows/release.yml](.github/workflows/release.yml)). Verify the
checksums before use:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf xai-oauth_<version>_linux_amd64.tar.gz   # unzip … on Windows
```

## Usage

```bash
# Device login, then automatically run the daemon in the background
./xai-oauth serve
# or: ./xai-oauth serve --no-browser
# Debug / stay attached: ./xai-oauth serve --foreground
# Save the printed local secret (if generated), e.g.:
export XAI_OAUTH_SECRET='…'
# Optional:
# export XAI_OAUTH_SOCKET=/path/to/daemon.sock

# Same terminal (or another) — control plane
./xai-oauth status
./xai-oauth token          # prints one access_token line
./xai-oauth logout         # clears memory and stops the background daemon
```

Default socket (full order: [docs/REFERENCE.md](docs/REFERENCE.md) §2.3):

1. `--socket` / `XAI_OAUTH_SOCKET`
2. `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` (if set)
3. `~/.xai-oauth/daemon.sock`
4. `$TMPDIR/xai-oauth/daemon.sock` only if home is unavailable (prefer setting home or `XAI_OAUTH_SOCKET`)

Windows: `%LOCALAPPDATA%\xai-oauth\daemon.sock`.

### CLI commands

| Command | Role |
|---------|------|
| `serve` | Converge to a healthy **background** daemon: take over a running one (no re-login) or device-code login; `--foreground` stays attached |
| `status` | Query daemon (requires secret) |
| `token` | Print usable `access_token` (requires secret) |
| `logout` | Clear session and stop daemon (requires secret) |
| `version` | Print version |
| `help` | Print usage |

There is **no** separate `login` command: sign-in happens inside `serve`.
After logout or reauth, run `serve` again.

### Upgrading without re-authorizing

`serve` against a running daemon **takes over its in-memory session** instead
of refusing: install the new binary, make sure `XAI_OAUTH_SECRET` matches the
running daemon, and run `serve` again — no browser, no device code, sub-second
switchover:

```bash
export XAI_OAUTH_SECRET='…'   # same secret the daemon uses
./xai-oauth serve             # "taking over the running daemon (no re-login)"
```

Notes:

- The first upgrade **from a version without takeover** still needs one
  re-login (`logout`, then `serve`); every upgrade after that is login-free.
- Scope or client-id changes in a new version require a fresh consent —
  re-login is unavoidable in that case.
- To switch accounts: `xai-oauth logout && xai-oauth serve`.
- In cron/scripts use `xai-oauth status || xai-oauth serve` so a healthy
  daemon is left alone instead of being replaced on every tick.

### Windows

Same commands from PowerShell; set the environment variable with `$env:`:

```powershell
.\xai-oauth.exe serve
$env:XAI_OAUTH_SECRET = '…'   # if serve printed a generated secret
.\xai-oauth.exe status
.\xai-oauth.exe token
.\xai-oauth.exe logout        # the detached daemon has no console; stop it this way
```

Default socket: `%LOCALAPPDATA%\xai-oauth\daemon.sock` (requires Windows 10
1803+ / Server 2019+ for AF_UNIX).

### Go SDK

API docs: [pkg.go.dev/github.com/fun7257/xai-oauth/client](https://pkg.go.dev/github.com/fun7257/xai-oauth/client)

```go
import (
    "context"

    "github.com/fun7257/xai-oauth/client"
)

func main() {
    // Secret: only from env XAI_OAUTH_SECRET (required).
    c, err := client.New(client.Config{
        // SocketPath defaults to XAI_OAUTH_SOCKET or DefaultSocketPath()
    })
    if err != nil {
        panic(err)
    }
    tok, err := c.Get(context.Background())
    if err != nil {
        panic(err)
    }
    // Authorization: Bearer <tok> → https://api.x.ai/...
    _ = tok
}
```

Or let the SDK inject the bearer for you — only `https://…x.ai` requests get
the token; every other host passes through untouched:

```go
hc := c.HTTPClient()
resp, err := hc.Get("https://api.x.ai/v1/models")
```

Other methods: `Status`, `Ready`, `WaitReady` (block until the daemon is
ready), `Health`, `Logout`, `SocketPath`, `Transport`, `CloseIdleConnections`.

Sentinel errors: `client.ErrUnreachable` (daemon down), `ErrUnauthorized`,
`ErrReauthRequired`, `ErrTierDenied`, `ErrUnavailable` (use `errors.Is`).

### Local HTTP API (over the Unix socket)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | none* | Liveness |
| GET | `/ready` | none* | Ready when session is usable |
| GET | `/status` | local secret | Non-sensitive state |
| GET | `/token` | local secret | Fresh access_token |
| POST | `/logout` | local secret | Wipe memory; process exits |

\*Server does not require secret on health/ready; the SDK always sends the secret.

Example with curl:

```bash
curl --unix-socket "$XAI_OAUTH_SOCKET" \
  -H "Authorization: Bearer $XAI_OAUTH_SECRET" \
  http://localhost/token
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `XAI_OAUTH_SECRET` | Local API secret for status/token/logout/SDK |
| `XAI_OAUTH_SOCKET` | Unix socket path |
| `HTTP(S)_PROXY` / `ALL_PROXY` / `NO_PROXY` | **Outbound** OAuth to `auth.x.ai` only (not used for UDS) |

OAuth **scopes are fixed** in code (personal default set). They are not
configurable via env.

## Public OAuth client

Device login uses a **public** client id (see `internal/protocol/constants.go`).
This is **not** a private API key, but upstream policy may still restrict or
revoke it. This project does **not** claim official approval by xAI.

## Troubleshooting

Most common cases (full table: [docs/REFERENCE.md §7](docs/REFERENCE.md#7-troubleshooting)):

- `daemon: down` — `serve` not running, or the CLI resolves a different
  socket path than the daemon; pin `XAI_OAUTH_SOCKET` on both sides.
- `unauthorized` — `XAI_OAUTH_SECRET` missing/mismatched; export the secret
  the serving process uses.
- `reauth_required` — refresh token rejected or logged out; run `serve` again.
- `socket … in use by a live process` — a previous daemon still serves there;
  `xai-oauth logout` it first.

The background daemon writes no logs by design; `xai-oauth status`
(`last_error`) is the diagnostic channel.

## Reference

Full command / HTTP / SDK / environment / troubleshooting tables:
**[docs/REFERENCE.md](docs/REFERENCE.md)**.

## Development

```bash
make help      # list targets
make check     # fmt-check + vet + test
make build     # ./xai-oauth
make test-race
make cover
make vuln      # govulncheck (known-vulnerability scan; needs network)
```

Builds auto-switch to the patched toolchain pinned in `go.mod`
(`toolchain go1.26.6+`); any installed Go ≥1.21 bootstraps it.

### CI

| Workflow | Trigger | What it does |
|----------|---------|----------------|
| [CI](.github/workflows/ci.yml) | push/PR to `main`, **daily schedule**, manual | `make check` + race on Ubuntu & macOS; vet/test/race on Windows; **govulncheck gate**; cross-build Linux/macOS/Windows (scheduled/manual uploads artifacts) |
| [Release](.github/workflows/release.yml) | tag `v*` | check + **govulncheck gate** + publish release binaries |

## License

[MIT](LICENSE)
