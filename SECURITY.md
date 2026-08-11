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
2. **Possession of the local secret** (`XAI_OAUTH_SECRET` / `--secret`)
3. **Process memory** of `serve` (access + refresh tokens, no disk by design)

Without the secret, `/token` / `/status` / `/logout` return 401.  
`/health` and `/ready` do not require the secret on the server (liveness);
the Go SDK still sends the secret on every call.

## Controls

| Control | Default |
|---------|---------|
| Listen | Unix domain socket only (CLI) |
| Socket file mode | `0600` after bind; parent dir `0700` |
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

- Prefer setting `XAI_OAUTH_SECRET` yourself for stable automation.
- If unset, `serve` generates a random secret and prints it **once** to stderr —
  treat it like a password; it is not written to disk by this tool.
- Do not commit secrets or put them in public bug reports.

## Unix socket hygiene

- Default paths under `$XDG_RUNTIME_DIR` or `~/.xai-oauth` are per-user.
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

1. Prefer a private report (e.g. GitHub Security Advisory when the repo is public).
2. Do **not** open a public issue that includes live tokens, refresh tokens,
   local secrets, or full captures containing credentials.

## Residual policy risk

Publishing or using a third-party tool that embeds a **public** OAuth client id
and xAI branding carries residual risk of allowlist/ToS/trademark policy changes.
This document does not provide legal advice.
