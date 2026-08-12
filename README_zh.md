# xai-oauth

**本机开发者工具** — 单操作者 xAI（Grok）OAuth sidecar。  
设备码登录一次后，会话**只放内存**，通过 **Unix domain socket**（HTTP）发放可用 `access_token`；业务自行请求 `https://api.x.ai`。

> **与 xAI 无隶属关系。** 非官方、社区维护软件。  
> **仅限本机** — 不是多租户或公网 token 服务。  
> 许可证：[MIT](LICENSE)。安全模型：[SECURITY.md](SECURITY.md)。  
> 设计：[DESIGN.md](DESIGN.md)。引用手册：[docs/REFERENCE.md](docs/REFERENCE.md)。  
> English: [README.md](README.md)。

## 安全与范围

| 应该 | 不要 |
|------|------|
| 使用默认 **仅属主可访问** 的 Unix socket（0600） | 当成共享/公网服务 |
| 只通过环境变量 **`XAI_OAUTH_SECRET`** 提供本机 secret（CLI **无** `--secret`） | 把 secret 写进命令行或可读脚本 |
| 将 OAuth access/refresh 当秘密 | 完整 token 进日志；`token` 的 stdout 也当秘密 |
| logout / reauth 后重新 `serve` | 指望进程重启后仍登录 |

能打开 socket **且** 持有本机 secret 的人，可以拿到 **你的** access_token 并消耗 **你的** 额度。

OAuth 使用**公开**设备码 client id（应用内无 client secret）。xAI 可能随时调整白名单或条款；风险自负。

## 归因

- 设备码 / refresh / host 校验等协议布局参考了 [xai-proxy](https://github.com/fun7257/xai-proxy)，以及其文档中述及的社区 OAuth 流程讨论（含 [Hermes Agent](https://github.com/NousResearch/hermes-agent) 脉络）。
- 默认 scope 对齐 **grok-build** / Grok CLI 风格个人默认（`grok-cli:access`、`api:access`、conversations/workspaces 等）。
- 本项目**独立**，与 xAI、Hermes Agent、Nous Research 或任何官方 Grok 产品**无隶属关系**。

## 用途 / 非用途

**用于：** 本机工具需要活的 xAI bearer，又不想自己实现 refresh。  
**不是：** 官方产品；`api.x.ai` 反代（见 **xai-proxy**）；落盘多账号 SSO。

## 依赖

- Go **1.26+**（见 `go.mod`）
- SuperGrok 或 X Premium+ 等 xAI 要求的 OAuth API 权限
- **Linux、macOS 或 Windows 10 1803+ / Server 2019+**（AF_UNIX socket）

控制面与 SDK 在所有平台上都**仅**使用 Unix domain socket（AF_UNIX），无 Named Pipe / TCP 回退。
Windows 上按用户隔离依赖默认 `%LOCALAPPDATA%\xai-oauth` 目录的 NTFS ACL（而非 POSIX 权限位），详见 [SECURITY.md](SECURITY.md)。

## 安装

源码构建（Go 1.26+）：

```bash
cd xai-oauth
make build                 # → ./xai-oauth
# 或: make install         # → ~/.local/bin/xai-oauth（make uninstall 卸载）
# 或不克隆仓库：
go install github.com/fun7257/xai-oauth/cmd/xai-oauth@latest
```

或下载发布包：打 `v*` tag 后，GitHub Actions 会构建 **Linux / macOS（`.tar.gz`）/
Windows（`.zip`）** 二进制并发布（见
[.github/workflows/release.yml](.github/workflows/release.yml)）。使用前校验：

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## 使用

```bash
# 设备码登录成功后自动挂后台
./xai-oauth serve
# 或: ./xai-oauth serve --no-browser
# 调试用前台: ./xai-oauth serve --foreground
export XAI_OAUTH_SECRET='…'   # 若 serve 打印了生成的 secret，请保存

# 同一终端或另一终端控制
./xai-oauth status
./xai-oauth token
./xai-oauth logout             # 清会话并停后台 daemon
```

默认 socket（完整顺序见 [docs/REFERENCE.md](docs/REFERENCE.md) §2.3）：

1. `--socket` / `XAI_OAUTH_SOCKET`
2. `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock`（若已设置）
3. `~/.xai-oauth/daemon.sock`
4. 若无法解析 home：`$TMPDIR/xai-oauth/daemon.sock`（多用户主机上较弱，请显式设路径）

Windows 默认：`%LOCALAPPDATA%\xai-oauth\daemon.sock`。

| 命令 | 作用 |
|------|------|
| `serve` | 设备码登录后**自动后台** daemon（UDS HTTP）；`--foreground` 保持前台 |
| `status` / `token` / `logout` | 控制面（**必须** secret） |
| `version` / `help` | 版本 / 用法 |

**没有**独立 `login` 子命令；登录只在 `serve` 内完成。

### Windows

PowerShell 下命令相同，环境变量用 `$env:` 设置：

```powershell
.\xai-oauth.exe serve
$env:XAI_OAUTH_SECRET = '…'   # 若 serve 打印了生成的 secret
.\xai-oauth.exe status
.\xai-oauth.exe logout        # 后台 daemon 无控制台，用 logout 停止
```

默认 socket：`%LOCALAPPDATA%\xai-oauth\daemon.sock`（需 Windows 10 1803+ / Server 2019+）。

### Go SDK

```go
// 须已 export XAI_OAUTH_SECRET（SDK 只读该环境变量）
c, err := client.New(client.Config{})
tok, err := c.Get(ctx)
// Authorization: Bearer <tok> → api.x.ai

// 或让 SDK 自动注入（仅对 https 的 x.ai 域生效，token 不会发给其它 host）：
hc := c.HTTPClient()
resp, err := hc.Get("https://api.x.ai/v1/models")
```

其它方法：`Status`、`Ready`、`WaitReady`（阻塞等 daemon 就绪）、`Health`、`Logout`、`SocketPath`、`Transport`、`CloseIdleConnections`。  
哨兵错误新增 `ErrUnreachable`（daemon 未运行），配合 `errors.Is` 使用。

### 本机 HTTP（Unix socket 上）

| 方法 | 路径 | 鉴权 |
|------|------|------|
| GET | `/health` `/ready` | 服务端可不校验 secret |
| GET | `/status` `/token` | 本机 secret |
| POST | `/logout` | 本机 secret |

```bash
curl --unix-socket "$XAI_OAUTH_SOCKET" \
  -H "Authorization: Bearer $XAI_OAUTH_SECRET" \
  http://localhost/token
```

## 环境变量

| 变量 | 用途 |
|------|------|
| `XAI_OAUTH_SECRET` | 本机 API secret |
| `XAI_OAUTH_SOCKET` | socket 路径 |
| `HTTP(S)_PROXY` 等 | **仅**出站访问 `auth.x.ai`（不用于 UDS） |

OAuth **scope 写死在代码中**，不可通过 env 配置。

## 公开 OAuth client

设备登录使用公开 client id（见 `internal/protocol/constants.go`）。  
这**不是**私钥式 API key，但上游策略仍可能限制或吊销。本项目**不声称**获得 xAI 官方背书。

## 故障排查

常见情况（完整表见 [docs/REFERENCE.md §7](docs/REFERENCE.md#7-troubleshooting)）：

- `daemon: down` — `serve` 未运行，或 CLI 与 daemon 解析出的 socket 路径不同；两侧显式设 `XAI_OAUTH_SOCKET`。
- `unauthorized` — `XAI_OAUTH_SECRET` 缺失或与 serve 进程不一致。
- `reauth_required` — refresh token 失效或已 logout；重新 `serve`。
- `socket … in use by a live process` — 旧 daemon 还在服务；先 `xai-oauth logout`。

后台 daemon 按设计不写日志；诊断通道是 `xai-oauth status` 的 `last_error`。

## 引用手册

命令、HTTP、SDK、环境变量、故障排查完整表：**[docs/REFERENCE.md](docs/REFERENCE.md)**。

## 开发

```bash
make help      # 列出目标
make check     # fmt-check + vet + test
make build     # ./xai-oauth
make test-race
make cover
```

### CI

| Workflow | 触发 | 内容 |
|----------|------|------|
| [CI](.github/workflows/ci.yml) | `main` 的 push/PR、**每日定时**、手动 | Ubuntu/macOS 上 `make check` + race；Windows 上 vet/test/race；交叉编译 Linux/macOS/Windows（定时/手动会上传 artifact） |
| [Release](.github/workflows/release.yml) | tag `v*` | check + 发布二进制 |

## 许可证

[MIT](LICENSE)
