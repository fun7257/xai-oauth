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
| 优先用环境变量 **`XAI_OAUTH_SECRET`**（少用 `--secret` 命令行） | 在 CI/共享机上把 secret 写进 argv |
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
- 支持 Unix socket 的系统（主路径）

## 安装

```bash
cd xai-oauth
make build                 # → ./xai-oauth
# 或: make install         # → ~/.local/bin/xai-oauth
```

## 使用

```bash
# 终端 1
./xai-oauth serve
# 或: ./xai-oauth serve --no-browser
export XAI_OAUTH_SECRET='…'   # 若 serve 打印了生成的 secret，请保存

# 终端 2
./xai-oauth status
./xai-oauth token
./xai-oauth logout
```

默认 socket（完整顺序见 [docs/REFERENCE.md](docs/REFERENCE.md) §2.3）：

1. `--socket` / `XAI_OAUTH_SOCKET`
2. `$XDG_RUNTIME_DIR/xai-oauth/daemon.sock`（若已设置）
3. `~/.xai-oauth/daemon.sock`
4. 若无法解析 home：`$TMPDIR/xai-oauth/daemon.sock`（多用户主机上较弱，请显式设路径）

| 命令 | 作用 |
|------|------|
| `serve` | 设备码登录 + 内存会话 + UDS HTTP |
| `status` / `token` / `logout` | 控制面（**必须** secret） |
| `version` | 版本 |

**没有**独立 `login` 子命令；登录只在 `serve` 内完成。

### Go SDK

```go
c, err := client.New(client.Config{Secret: os.Getenv("XAI_OAUTH_SECRET")})
tok, err := c.Get(ctx)
// Authorization: Bearer <tok> → api.x.ai
```

其它方法：`Status`、`Ready`、`Health`、`Logout`、`SocketPath`。

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

## 引用手册

命令、HTTP、SDK、环境变量完整表：**[docs/REFERENCE.md](docs/REFERENCE.md)**。

## 开发

```bash
make help      # 列出目标
make check     # fmt-check + vet + test
make build     # ./xai-oauth
make test-race
make cover
```

## 许可证

[MIT](LICENSE)
