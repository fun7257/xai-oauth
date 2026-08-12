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
- **Platforms:** Linux, macOS, and Windows 10 1803+ / Server 2019+. The
  control plane is AF_UNIX (HTTP over Unix domain sockets) on every platform;
  there is no Named Pipe or TCP fallback.

---

## 2. CLI

### 2.1 Synopsis

```text
xai-oauth <command> [flags]
```

| Command | Description | Requires running `serve` | Requires secret |
|---------|-------------|---------------------------|-----------------|
| `serve` | Converge to a healthy daemon: take over a running daemon's session (no re-login), else device-code login | — | Optional when nothing runs (generated); **required** to take over |
| `status` | Print daemon health / ready / session state | Yes | **Yes** |
| `token` | Print one line: usable `access_token` | Yes | **Yes** |
| `logout` | Clear memory session and stop daemon | Yes | **Yes** |
| `version` | Print version string | No | No |
| `help` | Print usage | No | No |

### 2.2 Flags

| Flag | Commands | Env fallback | Default | Meaning |
|------|----------|--------------|---------|---------|
| `--socket` | all control + serve | `XAI_OAUTH_SOCKET` | See §2.3 | Unix socket path |
| `--no-browser` | `serve` only | — | `false` | If set, do not auto-open browser; still print URL + code |
| `--foreground` | `serve` only | — | `false` | Stay attached after login (do not background) |
| `--from-login` | `serve` only (internal) | — | — | Child mode: read login handoff (secret + tokens) from stdin; not for operators |

Local API secret for the **CLI** is **env-only**: `XAI_OAUTH_SECRET` (no `--secret` flag).  
`serve` generates a random secret if the env is unset and prints it once; export it before control commands.

### 2.3 Default socket path

Resolution order for socket path:

1. `--socket` if non-empty  
2. else `XAI_OAUTH_SOCKET` if non-empty  
3. else (Unix) `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` if `XDG_RUNTIME_DIR` set  
4. else (Unix) `~/.xai-oauth/daemon.sock`  
5. else (Unix) `$TMPDIR/xai-oauth/daemon.sock` (home unavailable)

On Windows, the default (steps 3–5) is `%LOCALAPPDATA%\xai-oauth\daemon.sock`
(`os.UserCacheDir`).

On `serve` bind (Unix): parent directory must be mode **0700** **and owned by
the current UID** (else listen fails — refuse foreign/group-writable parents,
especially under `$TMPDIR`); socket file mode **0600**. On Windows POSIX modes
do not apply; isolation relies on the parent directory's NTFS ACLs (see
[SECURITY.md](../SECURITY.md)). On every platform an existing socket file at
the path is first probed with a connect: if something still accepts, `serve`
refuses (a live daemon is never silently orphaned); only genuinely stale
leftovers are removed. On shutdown, the path is removed best-effort.

### 2.4 `serve` lifecycle

1. Probe the socket. Decision matrix when a daemon already answers:
   - secret matches + session **ready** → **takeover**: `POST /handoff`
     transfers the in-memory session (access + refresh token) to this
     process; the old daemon drains and exits; **no device login, no
     browser**. This is the zero-reauth upgrade path.
   - secret matches + session sticky-dead (`reauth_required` /
     `tier_denied`) → device login first, then the dead daemon is stopped
     and replaced (its tokens were already wiped; nothing is lost).
   - `XAI_OAUTH_SECRET` unset or wrong → refuse (never disturbs a daemon it
     cannot authenticate to).
   - daemon predates `/handoff` → refuse with a hint (`logout`, then one
     final re-login).
2. Otherwise (nothing listening): resolve scope (fixed constant; see §6).  
3. Device-code OAuth against `auth.x.ai` (may open browser unless `--no-browser`).  
4. Print socket / secret (if generated) to stderr (**not** “serving” yet).  
5. **Default:** re-exec a detached daemon child (`setsid` on Unix;
   `DETACHED_PROCESS` on Windows; stdout/stderr → null device); pass
   **secret + tokens** once via stdin JSON handoff (never on
   child argv, never on disk; `XAI_OAUTH_SECRET` is stripped from the child's
   environment); parent waits until secret-authenticated
   `GET /status` reports `state=ready`, prints pid, then **exits 0**.  
6. **`--foreground`:** keep tokens in this process and serve until stop (no re-exec).  
7. Daemon listens HTTP on the Unix socket; holds access + refresh tokens in memory.  
8. Daemon exits on SIGINT/SIGTERM, failed serve, or successful `POST /logout`.
   The detached Windows child has no console (no Ctrl+C); stop it with
   `xai-oauth logout`.

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

`/ready` is true when `state=ready` **and** a `GET /token` can plausibly
succeed. When the access token is past expiry and the last refresh attempt
failed, `/ready` returns 503 with `state="degraded"` (self-heals after the
next successful refresh); sticky failures report `reauth_required` /
`tier_denied`.
| `GET` | `/status` | **Yes** | See §3.3 |
| `GET` | `/token` | **Yes** | `{"access_token":"...","token_type":"Bearer"}` |
| `POST` | `/logout` | **Yes** | `{"ok":true,"logged_out":true}` then process exit |
| `POST` | `/handoff` | **Yes** | Session snapshot **including the refresh token**; daemon drains and exits. Internal serve-takeover plumbing — not in the SDK; 409 `handoff_unavailable` when not ready |

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
| `state` | string | `ready` \| `reauth_required` \| `tier_denied` \| `handed_off` (shutting down after takeover) |
| `has_expiry` | bool | Whether an absolute expiry is known |
| `expires_at` | string | RFC3339 UTC when `has_expiry` |
| `token_valid` | bool | Held access token is hard-valid right now (false may still refresh fine) |
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
| 409 | `handoff_unavailable` | `/handoff` only: session not ready (dead or already handed off) |
| 503 | `unavailable` | Transient IdP/network failure, or daemon drained by a takeover (retry hits the successor) |

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

On Windows, `curl --unix-socket` support for AF_UNIX varies by curl build;
prefer the CLI (`xai-oauth status|token|logout`) or the Go SDK.

---

## 4. Go SDK (`github.com/fun7257/xai-oauth/client`)

Import path: module `github.com/fun7257/xai-oauth`, package `client`.

### 4.1 Construction

```go
// export XAI_OAUTH_SECRET=…  (required; only secret source)
c, err := client.New(client.Config{
    SocketPath: "", // optional; env or DefaultSocketPath()
})
```

| Field | Required | Resolution |
|-------|----------|------------|
| `SocketPath` | No | `Config.SocketPath` → `XAI_OAUTH_SOCKET` → `DefaultSocketPath()` |
| *(secret)* | **Yes** | **env only** `XAI_OAUTH_SECRET` (no Config field) |

Fixed client timeout: **30s** (shorten per call via ctx). No injectable
`http.Client`, no TCP `BaseURL`. `*Client` is safe for concurrent use.

### 4.2 Methods (`*Client`)

| Method | HTTP | Returns |
|--------|------|---------|
| `Get(ctx) (string, error)` | `GET /token` | access token |
| `Status(ctx) (*Status, error)` | `GET /status` | status struct |
| `Ready(ctx) (bool, State, error)` | `GET /ready` | ready flag + state |
| `WaitReady(ctx) error` | polls `GET /status` | nil once ready; fails fast on bad secret / sticky states |
| `Health(ctx) error` | `GET /health` | nil if alive |
| `Logout(ctx) error` | `POST /logout` | nil on success |
| `Transport(base) http.RoundTripper` | — | bearer-injecting transport (see §4.6) |
| `HTTPClient() *http.Client` | — | `&http.Client{Transport: c.Transport(nil)}` |
| `SocketPath() string` | — | configured socket path |
| `CloseIdleConnections()` | — | drop idle daemon connections |

### 4.2.1 Package helpers

| Function | Returns |
|----------|---------|
| `New(Config) (*Client, error)` | client (`XAI_OAUTH_SECRET` required) |
| `DefaultSocketPath() string` | default UDS path (see §2.3) |

### 4.3 `client.Status` struct and `State`

```go
type State string // StateReady | StateReauthRequired | StateTierDenied
                  // StateHandedOff (takeover shutdown window)
                  // (Ready only: StateDegraded | StateNotReady)

type Status struct {
    State      State
    HasExpiry  bool
    ExpiresAt  time.Time // zero when !HasExpiry
    TokenValid bool      // access token hard-valid right now
    LastError  string
}
```

Comparisons against string literals still compile (`st.State == "ready"`).

### 4.4 Sentinel errors

Use `errors.Is`:

| Variable | When |
|----------|------|
| `ErrUnreachable` | Daemon socket not reachable (not running / wrong path) |
| `ErrUnauthorized` | Local secret rejected |
| `ErrReauthRequired` | Need new `serve` / device login |
| `ErrTierDenied` | Tier/entitlement denial |
| `ErrUnavailable` | Transient failure; retry later |

### 4.5 Minimal app pattern

```go
// os.Setenv("XAI_OAUTH_SECRET", "…") or export in the shell
c, err := client.New(client.Config{})
if err != nil { /* handle */ }
tok, err := c.Get(ctx)
if err != nil { /* errors.Is unreachable / reauth / unavailable / ... */ }
// req.Header.Set("Authorization", "Bearer "+tok)
// http to https://api.x.ai/...
```

### 4.6 Bearer-injecting transport

```go
hc := c.HTTPClient() // or &http.Client{Transport: c.Transport(base)}
resp, err := hc.Get("https://api.x.ai/v1/models")
```

- Injects `Authorization: Bearer <access_token>` (fresh from the daemon per
  request; the daemon caches/refreshes) **only** for `https` requests whose
  host is `x.ai` or a true subdomain — the bearer can never leak to foreign
  origins.
- Requests to other schemes/hosts pass through unchanged without a token
  fetch; an existing `Authorization` header is never overwritten.
- The transport never mutates the caller's request (clones before injecting).

---

## 5. Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `XAI_OAUTH_SECRET` | CLI + SDK (only secret source; serve generates if empty) | Local API secret |
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
Device polling: total window capped at **30 minutes**, poll interval clamped
to **1–30s** (defensive bounds on IdP-provided `expires_in` / `interval`).

Public client id is **not** a confidential secret; upstream policy may still change allowlists or terms. See [README.md](../README.md) and [SECURITY.md](../SECURITY.md).

---

## 7. Troubleshooting

Symptom → likely cause → action. CLI messages appear on stderr; SDK errors
match the sentinels in §4.4 via `errors.Is`.

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `daemon: down` / `daemon not reachable` / SDK `ErrUnreachable` | No `serve` running, or CLI/SDK resolves a **different socket path** than the daemon (e.g. `XDG_RUNTIME_DIR` set in one shell but not the other) | Start `xai-oauth serve`; or pin the path explicitly on both sides with `XAI_OAUTH_SOCKET` / `--socket` |
| HTTP 401 `unauthorized` / SDK `ErrUnauthorized` | `XAI_OAUTH_SECRET` missing or different from the serving process | Export the secret printed by `serve` (or the one you exported before `serve`); restart `serve` if it was generated and lost |
| HTTP 401 `reauth_required` / SDK `ErrReauthRequired` | Refresh token rejected (`invalid_grant`), or session was logged out | Run `xai-oauth serve` again and complete device login |
| HTTP 403 `tier_denied` / SDK `ErrTierDenied` | Account lacks API entitlement for OAuth access (HTTP 403 from IdP) | Check subscription tier; retry after upgrading — state is sticky until a new `serve` |
| HTTP 503 `unavailable` / SDK `ErrUnavailable` | Transient IdP/network failure during refresh | Retry later; check `xai-oauth status` `last_error`; verify proxy env if egress goes through one |
| `/ready` 503 with `state="degraded"` | Access token expired **and** the last refresh failed | Usually transient — self-heals on the next successful refresh; inspect `last_error` |
| `daemon already running … but XAI_OAUTH_SECRET is not set` | `serve` found a live daemon but cannot authenticate a takeover | Export the daemon's secret and rerun `serve` (session is then preserved), or `xai-oauth logout` first |
| `daemon on … predates session takeover (no /handoff)` | The running daemon is an older version without the takeover endpoint | `xai-oauth logout`, then `serve` — one final re-login; later upgrades are login-free |
| `another takeover is in progress` | Two `serve` invocations raced | Wait a moment and check `xai-oauth status`; the winner's daemon should be `ready` |
| `socket … in use by a live process` | Bind retry window expired: a predecessor did not release the path in time, or a foreign process serves there | Retry `serve`; if it persists, inspect the process holding the socket, or choose a different `--socket` |
| `socket dir … must be mode 0700` / `not owned by current user` (Unix) | Socket parent dir is shared, group/world-accessible, or owned by another user | Point `--socket` / `XAI_OAUTH_SOCKET` at a private, user-owned directory |
| `listen` fails on Windows (address family / protocol error) | Windows before 10 1803 / Server 2019 — no AF_UNIX support | Upgrade Windows; there is no Named Pipe / TCP fallback |
| Generated secret lost (terminal closed) | Secret is printed once and never stored on disk | `xai-oauth logout` if reachable (or kill the daemon), then `serve` again with `XAI_OAUTH_SECRET` pre-exported |
| Daemon "disappears" after closing the terminal (Windows) | The detached child has no console; it does not exit, only its window is gone | It is still running — use `xai-oauth status` / `logout` to manage it |

The background daemon writes no logs (stdout/stderr → null device by design);
`xai-oauth status` (`last_error`) is the diagnostic channel.

---

## 8. Related docs

| Doc | Role |
|-----|------|
| [README.md](../README.md) | Getting started (EN) |
| [README_zh.md](../README_zh.md) | Getting started (ZH) |
| [DESIGN.md](../DESIGN.md) | Architecture & design decisions |
| [SECURITY.md](../SECURITY.md) | Threat model & reporting |
| [LICENSE](../LICENSE) | MIT |
