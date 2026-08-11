# xai-oauth reference

Normative command, API, SDK, and environment reference for the current tree.
For product intent and architecture, see [DESIGN.md](../DESIGN.md).
For threat model, see [SECURITY.md](../SECURITY.md).
For a short getting-started path, see [README.md](../README.md).

---

## 1. Process model

| Role | Process | Holds OAuth tokens? |
|------|---------|---------------------|
| Daemon | `xai-oauth serve` | Yes (memory only) |
| Control CLI | `status` / `token` / `logout` | No — HTTP client over UDS |
| App / SDK | `client` package | No — fetches access token from daemon |

- There is **no** offline `login` command. Sign-in runs inside `serve`.
- After `logout` or sticky reauth, run **`serve` again**.
- Tokens are **not** written to disk.
- **Platforms:** Linux and macOS only. **Windows is not supported** (CLI, SDK,
  and packages use `//go:build unix`; no Named Pipe or TCP control plane).

---

## 2. CLI

### 2.1 Synopsis

```text
xai-oauth <command> [flags]
```

| Command | Description | Requires running `serve` | Requires secret |
|---------|-------------|---------------------------|-----------------|
| `serve` | Device-code login, then serve HTTP on a Unix socket | — | Optional (generated if empty) |
| `status` | Print daemon health / ready / session state | Yes | **Yes** |
| `token` | Print one line: usable `access_token` | Yes | **Yes** |
| `logout` | Clear memory session and stop daemon | Yes | **Yes** |
| `version` | Print version string | No | No |
| `help` | Print usage | No | No |

### 2.2 Flags

| Flag | Commands | Env fallback | Default | Meaning |
|------|----------|--------------|---------|---------|
| `--socket` | all control + serve | `XAI_OAUTH_SOCKET` | See §2.3 | Unix socket path |
| `--secret` | all control + serve | `XAI_OAUTH_SECRET` | serve: random if empty; others: **error if empty** | Local API secret |
| `--no-browser` | `serve` only | — | `false` | If set, do not auto-open browser; still print URL + code |
| `--foreground` | `serve` only | — | `false` | Stay attached after login (do not background) |
| `--from-login` | `serve` only (internal) | — | — | Child mode: read login handoff from stdin; not for operators |

### 2.3 Default socket path

Resolution order for socket path:

1. `--socket` if non-empty  
2. else `XAI_OAUTH_SOCKET` if non-empty  
3. else `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` if `XDG_RUNTIME_DIR` set  
4. else `~/.xai-oauth/daemon.sock`  
5. else `$TMPDIR/xai-oauth/daemon.sock` (home unavailable)

On `serve` bind: parent directory must be mode **0700** **and owned by the current UID**
(else listen fails — refuse foreign/group-writable parents, especially under `$TMPDIR`);
socket file mode **0600**. Stale socket files at the path are removed before listen.
On shutdown, the path is removed best-effort.

### 2.4 `serve` lifecycle

1. Resolve scope (fixed constant; see §6).  
2. Device-code OAuth against `auth.x.ai` (may open browser unless `--no-browser`).  
3. Print socket / secret (if generated) to stderr.  
4. **Default:** re-exec a detached daemon child (`setsid`), pass tokens once via
   stdin JSON handoff (never written to disk); parent waits until `/health` is up,
   prints pid, then **exits 0** so the terminal is free.  
5. **`--foreground`:** keep tokens in this process and serve until stop (no re-exec).  
6. Daemon listens HTTP on the Unix socket; holds access + refresh tokens in memory.  
7. Daemon exits on SIGINT/SIGTERM, failed serve, or successful `POST /logout`.

### 2.5 `status` output (typical)

```text
daemon: up
socket: /path/to/daemon.sock
ready:  true
state:  ready
expires_at: 2026-...
last_error: ...    # only if set; non-sensitive short codes
```

If the socket is unreachable: `daemon: down` and non-zero exit.

### 2.6 `token` output

- **stdout:** single line, raw access token only (no JSON).  
- Suitable for: `Authorization: Bearer $(xai-oauth token)`.

### 2.7 Exit behaviour

- Success: exit `0`.  
- Errors: message on stderr, non-zero exit.  
- `logout` success: session cleared; daemon process shuts down shortly after.

---

## 3. Local HTTP API (Unix socket)

All routes below are served by `serve` on the Unix socket.  
Clients should use HTTP over UDS (not a TCP port).

Synthetic URL origin used by the Go SDK: `http://xai-oauth.local`  
(Host is ignored for dialing; transport dials `unix` only.)

### 3.1 Routes

| Method | Path | Local secret required (server) | Success body (JSON) |
|--------|------|--------------------------------|---------------------|
| `GET` | `/health` | No | `{"ok":true}` |
| `GET` | `/ready` | No | `{"ready":true}` or `{"ready":false,"state":"..."}` + HTTP 503 |
| `GET` | `/status` | **Yes** | See §3.3 |
| `GET` | `/token` | **Yes** | `{"access_token":"...","token_type":"Bearer"}` |
| `POST` | `/logout` | **Yes** | `{"ok":true,"logged_out":true}` then process exit |

### 3.2 Authentication

```http
Authorization: Bearer <local_secret>
```

- Compared with constant-time digest equality (not raw string early-exit length leak).  
- Wrong/missing secret on protected routes → HTTP **401**  
  `{"error":"unauthorized","message":"invalid local secret"}`.

The Go SDK **always** sends the secret on every request, including `/health` and `/ready`.

### 3.3 `/status` fields

| Field | Type | Notes |
|-------|------|--------|
| `state` | string | `ready` \| `reauth_required` \| `tier_denied` |
| `has_expiry` | bool | Whether an absolute expiry is known |
| `expires_at` | string | RFC3339 UTC when `has_expiry` |
| `last_error` | string | Short non-sensitive code/message; no IdP bodies |

### 3.4 `/token` semantics

- Returns a token the daemon considers usable **now**.  
- May refresh using the in-memory refresh token before responding.  
- Concurrent callers share a singleflight refresh.  
- Proactive refresh window: **5 minutes** before expiry (fixed).  
- No `expires_at` in the success body (clients need not parse JWT).

### 3.5 Error responses (JSON)

| HTTP | `error` | Meaning |
|------|---------|---------|
| 401 | `unauthorized` | Bad local secret |
| 401 | `reauth_required` | Refresh dead / logged out; run `serve` again |
| 403 | `tier_denied` | Account not entitled for API (refresh 403) |
| 503 | `unavailable` | Transient IdP/network failure |

### 3.6 curl examples

```bash
SOCK="${XAI_OAUTH_SOCKET:-$XDG_RUNTIME_DIR/xai-oauth/daemon.sock}"
# or: SOCK="$HOME/.xai-oauth/daemon.sock"

curl --unix-socket "$SOCK" http://localhost/health

curl --unix-socket "$SOCK" \
  -H "Authorization: Bearer $XAI_OAUTH_SECRET" \
  http://localhost/token

curl --unix-socket "$SOCK" -X POST \
  -H "Authorization: Bearer $XAI_OAUTH_SECRET" \
  http://localhost/logout
```

---

## 4. Go SDK (`github.com/fun7257/xai-oauth/client`)

Import path: module `github.com/fun7257/xai-oauth`, package `client`.

### 4.1 Construction

```go
c, err := client.New(client.Config{
    SocketPath: "", // optional; env or DefaultSocketPath()
    Secret:     os.Getenv("XAI_OAUTH_SECRET"),
})
```

| Field | Required | Resolution |
|-------|----------|------------|
| `Secret` | **Yes** (after resolve) | `Config.Secret` → `XAI_OAUTH_SECRET` |
| `SocketPath` | No | `Config.SocketPath` → `XAI_OAUTH_SOCKET` → `DefaultSocketPath()` |

Fixed client timeout: **30s**. No injectable `http.Client`, no TCP `BaseURL`.

### 4.2 Methods (`*Client`)

| Method | HTTP | Returns |
|--------|------|---------|
| `Get(ctx) (string, error)` | `GET /token` | access token |
| `Status(ctx) (*Status, error)` | `GET /status` | status struct |
| `Ready(ctx) (bool, string, error)` | `GET /ready` | ready flag + state |
| `Health(ctx) error` | `GET /health` | nil if alive |
| `Logout(ctx) error` | `POST /logout` | nil on success |
| `SocketPath() string` | — | configured socket path |

### 4.2.1 Package helpers

| Function | Returns |
|----------|---------|
| `New(Config) (*Client, error)` | client (secret required) |
| `DefaultSocketPath() string` | default UDS path (see §2.3) |

### 4.3 `client.Status` struct

```go
type Status struct {
    State     string // ready | reauth_required | tier_denied
    HasExpiry bool
    ExpiresAt string // RFC3339
    LastError string
}
```

### 4.4 Sentinel errors

Use `errors.Is`:

| Variable | When |
|----------|------|
| `ErrUnauthorized` | Local secret rejected |
| `ErrReauthRequired` | Need new `serve` / device login |
| `ErrTierDenied` | Tier/entitlement denial |
| `ErrUnavailable` | Transient failure; retry later |

Dial failures (daemon down) are ordinary wrapped network errors, not the sentinels above.

### 4.5 Minimal app pattern

```go
c, err := client.New(client.Config{Secret: secret})
if err != nil { /* handle */ }
tok, err := c.Get(ctx)
if err != nil { /* errors.Is reauth / unavailable / ... */ }
// req.Header.Set("Authorization", "Bearer "+tok)
// http to https://api.x.ai/...
```

---

## 5. Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `XAI_OAUTH_SECRET` | CLI, SDK | Local API secret |
| `XAI_OAUTH_SOCKET` | CLI, SDK | Unix socket path |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` (and lowercase) | `serve` egress only | Outbound OAuth to `auth.x.ai` |

**Not** used for local UDS traffic.  
**No** `XAI_OAUTH_SCOPES` or `XAI_OAUTH_ADDR` (removed by design).

---

## 6. Upstream OAuth (egress)

Fixed personal device-client parameters (`internal/protocol/constants.go`):

| Item | Value |
|------|--------|
| Issuer | `https://auth.x.ai` |
| Client ID | `b1a00492-073a-47ea-816f-4c329264a828` (public device client) |
| Scope | `openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write` (**fixed**) |
| Device | `POST https://auth.x.ai/oauth2/device/code` |
| Discovery | `GET https://auth.x.ai/.well-known/openid-configuration` |
| Token | discovery `token_endpoint` (https; host must be true `x.ai` subdomain) |

IdP timeouts: **20s** per discovery/device/refresh HTTP call.  
Refresh skew: **5 minutes** before access expiry.

Public client id is **not** a confidential secret; upstream policy may still change allowlists or terms. See [README.md](../README.md) and [SECURITY.md](../SECURITY.md).

---

## 7. Related docs

| Doc | Role |
|-----|------|
| [README.md](../README.md) | Getting started (EN) |
| [README_zh.md](../README_zh.md) | Getting started (ZH) |
| [DESIGN.md](../DESIGN.md) | Architecture & design decisions |
| [SECURITY.md](../SECURITY.md) | Threat model & reporting |
| [LICENSE](../LICENSE) | MIT |
