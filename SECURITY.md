# Security

Operator security notes and threat model for **xai-oauth**.  
Architecture: [DESIGN.md](DESIGN.md). User docs: [README.md](README.md).

## What this project is

**xai-oauth** is a **local developer tool**: a single-operator, machine-local
OAuth sidecar that holds your xAI session in **memory** and issues access
tokens over a **Unix domain socket** (HTTP).

It is **not**:

- an xAI / Grok / SuperGrok official product
- a multi-tenant or public SaaS token service
- a reverse proxy for `api.x.ai` (see **xai-proxy** for local API reverse proxy)

## Intended deployment

| Intended | Not intended |
|----------|----------------|
| **Linux / macOS** with Unix domain sockets | **Windows** (unsupported; no UDS control plane) |
| Unix socket owned by your user (`0600`) | Shared host multi-user trust |
| One human operator, one OAuth session in one `serve` process | Network-exposed token minting |
| CLI/SDK with the same local secret as `serve` | Shipping auto-generated secrets in git or tickets |

## Threat model

Anyone who can connect to the daemon socket **and** present a valid local
secret can:

- Obtain a live **OAuth access token** for your account
- Call `api.x.ai` as you (quota, rate limits, billable usage depending on tier)

Attack surface is roughly:

1. **Socket reachability** (filesystem permissions on the `.sock` path)
2. **Possession of the local secret** (env `XAI_OAUTH_SECRET` only for CLI)
3. **Process memory** of `serve` (access + refresh tokens, no disk by design)

Without the secret, `/token` / `/status` / `/logout` return 401.  
`/health` and `/ready` do not require the secret on the server (liveness);
the Go SDK still sends the secret on every call.

## Controls

| Control | Default |
|---------|---------|
| Listen | Unix domain socket only (CLI) |
| Socket file mode | `0600` after bind; parent dir `0700` **and owned by the serving UID** (listen fails otherwise) |
| Local authentication | Required for `/token`, `/status`, `/logout` (constant-time secret compare via SHA-256 digests) |
| Open without secret (server) | `/health`, `/ready` only |
| Token storage | **Memory only** — lost on process exit; no `tokens.json` |
| Upstream OAuth | HTTPS to `auth.x.ai`; host pin to true `x.ai` DNS labels |
| Device verification URL | https + x.ai host pin; user_code charset/length limits |
| Logging | Must not log full access/refresh tokens |
| Scopes | Fixed personal set in code (not env-overridable) |

## OAuth credentials

- Uses a **public** OAuth device-code client id (no confidential client secret
  in the app). See `internal/protocol/constants.go`.
- Refresh tokens are **rotated** (single-use family semantics on the IdP side).
  This process is single-instance; no multi-process file lock.
- Terminal refresh failures (`invalid_grant` / `invalid_client`) stick
  `reauth_required` until you restart `serve` and complete device login again.
- HTTP **403** on refresh is treated as **tier/entitlement denial**.
- Upstream policy (allowed clients, scopes, tiers) can change without notice.

## Local secret

- **CLI: environment only** — `XAI_OAUTH_SECRET`. There is **no** `--secret`
  flag (avoids argv leakage via `ps` / `/proc/*/cmdline`).
- Source the variable from a private file or shell profile if needed; do not
  paste it into shared scripts.
- If unset, `serve` generates a random secret and prints it **once** to stderr —
  `export XAI_OAUTH_SECRET='…'` before `status` / `token` / `logout`. It is not
  written to disk by this tool. Stderr may still enter terminal scrollback or
  session recorders.
- Background daemon children receive the secret once via stdin handoff (not env,
  not argv on the child).
- Go SDK reads the secret **only** from `XAI_OAUTH_SECRET` (no `Config.Secret`).
- `xai-oauth token` prints a full OAuth **access token** on stdout — treat that
  stream as secret (shell history, CI logs, screen shares).
- Do not commit secrets or put them in public bug reports.

## Unix socket hygiene

- Default path resolution (same as the SDK):
  1. `XAI_OAUTH_SOCKET` / `--socket`
  2. `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` if set
  3. `~/.xai-oauth/daemon.sock`
  4. `$TMPDIR/xai-oauth/daemon.sock` only if home is unavailable (weaker
     multi-user namespace; prefer setting home or `XAI_OAUTH_SOCKET`)
- Socket file mode `0600`; parent dir mode `0700` **and owned by the serving UID**
  after bind (foreign-owned or group/other-accessible parents are refused).
- Same-UID processes can still open a `0600` socket; the **secret** is the
  second control. Do not run untrusted code as your user while `serve` is up.
- Stale sockets from crashed processes are removed on next successful `serve`
  bind when the path is a leftover socket file.

## Outbound proxy

Standard `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` affect
**egress** to xAI (device code / discovery / refresh) only. They are **not**
used for the local Unix socket.

## Reporting vulnerabilities

If you believe you found a security issue **in this software** (not in xAI’s
upstream API):

1. Prefer a **private** channel first:
   - Enable and use **GitHub private vulnerability reporting** / Security
     Advisories when the repository is on GitHub (recommended before making
     the repo public).
   - If that is not yet configured, contact the maintainers privately by the
     means published on the repository (do not open a public issue with
     secrets).
2. Do **not** open a public issue that includes live tokens, refresh tokens,
   local secrets, or full captures containing credentials.

## Residual operator risks (before/after public release)

Keep these explicit when publishing or operating:

| Risk | Note |
|------|------|
| Same-UID access | Socket `0600` + secret; untrusted same-user code can still steal tokens |
| Memory-only session | Process dump / debugger can see AT/RT; restart clears login |
| `token` stdout / generated secret stderr | Easy to leak via logs, history, recorders |
| Public device client id | Upstream may change allowlists/ToS; not an official xAI product |
| No multi-tenant deployment | Not a shared gateway |

## Residual policy risk

Publishing or using a third-party tool that embeds a **public** OAuth client id
and xAI branding carries residual risk of allowlist/ToS/trademark policy changes.
This document does not provide legal advice.
