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
| Prefer **`XAI_OAUTH_SECRET` env** (not `--secret` argv) | Put secrets on the command line in CI/shared hosts |
| Treat OAuth access/refresh tokens as secrets | Log full tokens or leave `token` stdout in world-readable CI logs |
| Restart `serve` after logout / reauth | Expect tokens to survive process restart |

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
- Linux/macOS with Unix domain sockets (primary path)

## Install

```bash
cd xai-oauth
make build                 # → ./xai-oauth
# or: make install         # → ~/.local/bin/xai-oauth
```

Tagged releases (`v*`) publish Linux / macOS / Windows binaries via GitHub Actions
(see [.github/workflows/release.yml](.github/workflows/release.yml)).

## Usage

```bash
# Terminal 1 — device login, then serve on a Unix socket
./xai-oauth serve
# or: ./xai-oauth serve --no-browser
# Save the printed local secret (if generated), e.g.:
export XAI_OAUTH_SECRET='…'
# Optional:
# export XAI_OAUTH_SOCKET=/path/to/daemon.sock

# Terminal 2 — control plane (same socket + secret)
./xai-oauth status
./xai-oauth token          # prints one access_token line
./xai-oauth logout         # clears memory and stops serve
```

Default socket (full order: [docs/REFERENCE.md](docs/REFERENCE.md) §2.3):

1. `--socket` / `XAI_OAUTH_SOCKET`
2. `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` (if set)
3. `~/.xai-oauth/daemon.sock`
4. `$TMPDIR/xai-oauth/daemon.sock` only if home is unavailable (prefer setting home or `XAI_OAUTH_SOCKET`)

### CLI commands

| Command | Role |
|---------|------|
| `serve` | Device-code login + in-memory session + UDS HTTP |
| `status` | Query daemon (requires secret) |
| `token` | Print usable `access_token` (requires secret) |
| `logout` | Clear session and stop daemon (requires secret) |
| `version` | Print version |

There is **no** separate `login` command: sign-in happens inside `serve`.
After logout or reauth, run `serve` again.

### Go SDK

```go
import (
    "context"
    "os"

    "github.com/fun7257/xai-oauth/client"
)

func main() {
    c, err := client.New(client.Config{
        Secret: os.Getenv("XAI_OAUTH_SECRET"),
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

Other methods: `Status`, `Ready`, `Health`, `Logout`, `SocketPath`.

Sentinel errors: `client.ErrUnauthorized`, `ErrReauthRequired`, `ErrTierDenied`,
`ErrUnavailable` (use `errors.Is`).

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

## Reference

Full command / HTTP / SDK / environment tables: **[docs/REFERENCE.md](docs/REFERENCE.md)**.

## Development

```bash
make help      # list targets
make check     # fmt-check + vet + test
make build     # ./xai-oauth
make test-race
make cover
```

## License

[MIT](LICENSE)
