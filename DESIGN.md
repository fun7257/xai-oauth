# xai-oauth 设计方案

> 本机 OAuth sidecar（**路线 B：纯 daemon 控制面**）：`serve` 设备码登录后会话仅存内存；  
> `status` / `token` / `logout` 与 SDK 通过 **Unix socket 上的 HTTP** 操作该进程；  
> 客户端拿到 `access_token` 后直连 `api.x.ai`。

**状态：** 已实现（路线 B：本地单操作者可用）  

**许可证：** [MIT](LICENSE)  
**对外说明：** [README.md](README.md) · [SECURITY.md](SECURITY.md) · [docs/REFERENCE.md](docs/REFERENCE.md)  

**参考：** [xai-proxy](https://github.com/fun7257/xai-proxy)（协议布局）、grok-build 个人 OAuth2 默认 scope；  
设备码/refresh 社区流程脉络参见 xai-proxy 对 [Hermes Agent](https://github.com/NousResearch/hermes-agent) 的说明。  
本项目独立，与 xAI / Hermes / Nous **无隶属关系**。

---

## 1. 目标与非目标

### 目标

| 目标 | 说明 |
|------|------|
| 客户端最简 | SDK/`token` 子命令取 AT，调 `api.x.ai` |
| 自动保活 | serve 进程内提前刷新与 RT 轮换 |
| 简单高效 | 单进程、**内存会话不落盘**、stdlib HTTP |
| 安全默认 | Unix socket 0600 + 本机 secret；敏感路由鉴权 |
| CLI | `serve` / `status` / `token` / `logout` / `version`（路线 B） |
| 账号模式 | 仅 **xAI OAuth2 个人** |

### 非目标

- 反代 `api.x.ai`、**落盘 token**、独立 `login` 子命令
- Team / 企业 IdP、热重登 UI、多账号
- 多进程 flock / sibling adopt
- **Windows**（无 UDS 控制面 / Named Pipe / 本机 TCP 回退；仅 Linux / macOS）

---

## 2. 架构（路线 B）

```text
xai-oauth serve     ──设备码──► 内存 Session ──HTTP/UDS──► *.sock (0600)
      ▲                              │
      │         status/token/logout  │
      └──────── CLI / SDK ───────────┘
                                     │
本机应用 ◄── access_token ───────────┘
      │
      └── Bearer ──► api.x.ai
```

- **传输：** Unix domain socket（默认顺序：`$XDG_RUNTIME_DIR/xai-oauth/daemon.sock` → `~/.xai-oauth/daemon.sock` → `$TMPDIR/xai-oauth/daemon.sock`），socket 文件 **0600**，父目录 **0700 且属主为当前 UID**（否则拒绝 listen）  
- **协议：** HTTP（`GET /token` 等）跑在 Unix socket 上  
- **唯一持有凭证的进程：** `serve`  
- **重登：** 再次执行 `serve`  
- **logout：** 清内存并退出 serve  
- **无 TCP 本机服务路径**（SDK 仅 UDS）

---

## 3. 客户端契约

### 3.0 CLI

```text
xai-oauth serve   [--socket] [--no-browser] [--foreground]
                  # 设备码登录；默认 re-exec 后台 daemon，--foreground 保持前台
xai-oauth status  [--socket]                             # 查 daemon
xai-oauth token   [--socket]                             # 打印 access_token
xai-oauth logout  [--socket]                             # 清会话并停 daemon
xai-oauth version
```

`status`/`token`/`logout` 要求 **serve 已在跑**，且环境变量 **`XAI_OAUTH_SECRET`** 与 serve 一致（CLI **无** `--secret` 旗标）。

### 3.1 HTTP

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| GET | `/health` | 无 | 进程存活 |
| GET | `/ready` | 无 | state==ready 且 token 可用（refresh 失败且 AT 过期 → 503 `degraded`） |
| GET | `/status` | secret | state / expires_at / token_valid / last_error |
| GET | `/token` | secret | 可用 access_token |
| POST | `/logout` | secret | 清内存；serve 随后退出 |

```http
GET /token
Authorization: Bearer <local_secret>
```

成功 200：`{"access_token":"...","token_type":"Bearer"}`。

| HTTP | error | 动作 |
|------|-------|------|
| 401 | `unauthorized` | 修正 secret |
| 401 | `reauth_required` | 重新 `xai-oauth serve` 完成设备码 |
| 403 | `tier_denied` | 账号无 API 权益 |
| 503 | `unavailable` | 稍后重试 |

### 3.2 Go SDK（`github.com/fun7257/xai-oauth/client`）

```go
import "github.com/fun7257/xai-oauth/client"

// 须 export XAI_OAUTH_SECRET（SDK 只认环境变量）
c, err := client.New(client.Config{
    // SocketPath 默认：XAI_OAUTH_SOCKET 或 DefaultSocketPath()
})
tok, err := c.Get(ctx)
```

- **仅** Unix socket + HTTP；`Config` 只有 `SocketPath`；secret **仅** `XAI_OAUTH_SECRET`  
- 方法：`Get` / `Status` / `Ready` / `Health` / `Logout` / `SocketPath`  
- 无包级 `Get`、无 `NewWithoutSecret`、无 TCP `BaseURL`

---

## 4. OAuth 协议（xAI 个人）

| 项 | 定值 |
|----|------|
| Issuer | `https://auth.x.ai` |
| Client ID | `b1a00492-073a-47ea-816f-4c329264a828` |
| Scope | 见下（grok-build 个人默认） |
| Device | `POST https://auth.x.ai/oauth2/device/code` |
| Discovery | `GET https://auth.x.ai/.well-known/openid-configuration` |
| Token | discovery 的 `token_endpoint`（须 https；host 为 x.ai 真子域） |

### Scope（固定 = grok-build 个人 `default_oauth2_scopes`）

```text
openid profile email offline_access
grok-cli:access api:access
conversations:read conversations:write
workspaces:read workspaces:write
```

**不可配置**（无 env/flag）。不含 Team scope。

### 启动

1. discovery → 校验 token_endpoint  
2. device/code → 校验 user_code（≤64, `[A-Za-z0-9-]`）与 verification URI（https、x.ai 真子域、≤2048）后打印/开浏览器（`--no-browser` 可关）  


3. 轮询换 token（必须含 access + refresh；轮询窗口 ≤30 分钟、间隔钳制 1–30s）  
4. 写入内存 Session，state=ready  
5. 监听 HTTP  

登录失败则进程非 0 退出，不绑端口。

### GetAccessToken

- skew 固定 **5 分钟**；`now >= exp - skew` 则 refresh  
- singleflight；成功则轮换 AT，新 RT 为空则保留旧 RT  
- `invalid_grant` / `invalid_client` → `reauth_required`（粘性，不再打 IdP）  
- HTTP 403 → `tier_denied`  
- 网络/429/5xx → 不改 RT；AT 仍硬有效则返回，否则 `unavailable`  

无 expires_in 且无法解析 JWT exp：每次 GET /token 都 refresh。

恢复 reauth/tier：只能重启进程重新登录。

---

## 5. 本机 HTTP API（跑在 Unix socket 上）

默认 socket：见 §6。

| 路径 | 鉴权 | 说明 |
|------|------|------|
| GET /health | 无* | 存活（*服务端不强制 secret；SDK 仍带 secret） |
| GET /ready | 无* | state==ready 且 token 可用（降级时 503 `degraded`） |
| GET /status | secret | state / expires_at / token_valid / last_error |
| GET /token | secret | 可用 AT |
| POST /logout | secret | 清内存；serve 随后退出 |

Secret：仅 **`XAI_OAUTH_SECRET`**（CLI 无 `--secret`）；serve 未设置时可随机生成并打印一次。  
CLI 的 status/token/logout **必须**已 export 该环境变量。

---

## 6. 配置

| 来源 | 名称 | 默认 |
|------|------|------|
| flag | `--socket` | `$XDG_RUNTIME_DIR/…` → `~/.xai-oauth/…` → `$TMPDIR/…`（见 REFERENCE §2.3） |
| flag | `--no-browser` | false（默认尝试打开浏览器） |
| flag | `--foreground` | false（登录成功后默认后台 re-exec daemon） |
| env | `XAI_OAUTH_SOCKET` | 覆盖默认 socket 路径 |
| env | `XAI_OAUTH_SECRET` | 本机 API secret（CLI **唯一**来源；serve 空则生成） |
| env | 标准 `HTTP(S)_PROXY` 等 | 仅出站 IdP；**不**用于 UDS |

监听：`net.Listen("unix", path)`，socket **0600**，父目录 **0700 且属主为当前 UID**。  
HTTP：`ReadHeaderTimeout` / `ReadTimeout` / `WriteTimeout` / `IdleTimeout` / `MaxHeaderBytes`。

---

## 7. 代码结构

```text
cmd/xai-oauth/main.go   # sidecar 进程
client/                 # 对外 SDK（Get access_token）
internal/protocol/
internal/session/
internal/server/
```

---

## 8. 验收

1. `serve` 在 Unix socket 上监听；`token`/SDK `Get` 经 UDS 取 AT  
2. 进入 skew 后仍能拿到可用 token  
3. 并发 refresh 只打一次 IdP  
4. invalid_grant → 稳定 reauth_required  
5. logout（Clear）与在途 refresh 竞态：不恢复 token  
6. 日志无完整 token；socket 文件 0600  
7. CLI/SDK **仅** UDS；status/token/logout 与 SDK 均需 secret
