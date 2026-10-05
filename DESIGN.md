# fap 设计文档

> 一个开源、可托管的内网穿透平台：frp 的数据面 + 向日葵式的零配置设备托管。

## 1. 设计目标

1. **客户端零配置**：安装后自动出现在控制台「我的设备」列表里。
2. **Web 控制台集中管理**：所有隧道规则在浏览器里编辑，热下发到客户端，无需重启。
4. **单端口承诺**：对外只需要开一个端口（默认 443），HTTP 按 Host/Path 路由、SNI 直通、访问器按 tunnel 名接入。
5. **多层认证**：从明文 token（开发友好）→ HMAC-SHA256 → Ed25519 PK（生产推荐）。
6. **可运营**：审计、ACL、限流、节流、指标五件套。
7. **单机部署即可**：单 Rust 进程，开源 worktrees+tracing+toml；自托管式单机部署不强制依赖 master/worker。

## 2. 总体架构

```
                          公网（单端口 :443）
                                 │
                 ┌───────────────┴────────────────┐
                 │   gateway (Rust 单进程)        │
                 │                                │
                 │  shared_port                    │
                 │   ├─ HTTP 嗅探 → 解析 Host/Path │── 反代 ──▶ console (Next.js :3000)
                 │   ├─ TLS ClientHello 嗅探 SNI  │
                 │   └─ access_request 握手       │
                 │                                │
                 │  control (注册/心跳/配置下发)   │
                 │  data    (agent 回连，StreamConn)│
                 │  admin   (axum / 控制台 API)    │
                 │  metrics (AtomicU64 计数)      │
                 │  audit   (内存 ring buffer + 文件)│
                 └───────────────┬────────────────┘
                                 │ TLS + yamux 多路复用（v1=v1 帧，M5 升级）
                 ┌───────────────┴────────────────┐
                 │   agent (Rust 单二进制)        │
                 │   ├─ 注册 / 心跳 / 元信息上报  │
                 │   ├─ 隧道客户端 + 流量转发      │
                 │   ├─ rust-embed 嵌入本地管理页  │ ──▶ 127.0.0.1:7800（仅本机）
                 │   └─ Ed25519 密钥对（开机生成）  │
                 └───────────────┬────────────────┘
                                 │
                 ┌───────────────┴────────────────┐
                 │   内网真实服务（任意）         │
                 └────────────────────────────────┘

  控制台（Next.js + Tailwind v4 + shadcn）
    ├─ 服务端控制台：网关按 Host 反代，本机 Next.js 进程
    └─ agent 本地页：next build (output: 'export') → rust-embed
```

## 3. crate 划分

| crate | 职责 |
|---|---|
| `protocol` | 帧编解码、消息定义、wire format 锁定测试 |
| `gateway` | 网关核心（注册表、路由、流匹配、admin API、shared_port、metrics） |
| `agent` | 客户端核心（注册会话、心跳、开流处理、重连） |
| `demo` | 一条命令跑通完整链路 |
| `access` | fap-access 二进制：用户侧访问器，按 tunnel_id+token 接入 |

依赖方向：protocol → 无；agent → protocol；demo → agent + gateway + protocol；access → protocol。

## 4. 协议（fap-protocol）

帧格式：`[u32 BE 长度][类型 u8][JSON 载荷]`，长度 = 1 + 载荷字节数，MAX_FRAME_LEN = 4 MiB。

| 类型字节 | 消息 | 方向 | 用途 |
|---|---|---|---|
| 1 | `Register` | agent→gw | 设备首次注册，HMAC 响应或 PK 签名应答 |
| 2 | `RegisterAck` | gw→agent | 接受/拒绝，applied_tunnels、data_port、listeners |
| 3 | `Heartbeat` | 双向 | ts_ms |
| 4 | `HeartbeatAck` | 双向 | 回显 ts |
| 5 | `OpenStream` | gw→agent | 用户访问到达，开数据连接 |
| 6 | `StreamConn` | agent→gw | 数据连接首帧声明流 ID，后续裸字节流 |
| 7 | `ConfigPush` | gw→agent | 控制台下发的完整配置（覆盖 agent 持有的） |
| 8 | `ConfigAck` | agent→gw | 应用结果 |
| 9 | `AccessRequest` | access→gw | 访问器首帧，tunnel_id + token |
| 10 (M2.5c) | `AuthChallenge` | gw→agent | gateway nonce + ts |
| 11 (M2.5c) | `AuthChallengeResp` | agent→gw | HMAC(secret, nonce||ts) |
| 12 (M2.5d) | `PkRegister` | agent→gw | 携带设备元信息 + Ed25519 公钥 |
| 13 (M2.5d) | `PkRegisterAck` | gw→agent | 公钥被认可或拒绝 |
| 14 (M5b) | `AdminAuthChallenge` | admin→console | admin API 的挑战响应（避免 Bearer 令牌在日志泄露） |

wire format 锁定测试：`crates/protocol/tests/` 下每个消息都要有 roundtrip + JSON 形状测试。

## 5. 隧道路由模型（TunnelRouter）

四种暴露形式（同一 `TunnelConfig` 上至少其一）：

| 字段 | 用途 | 共享单端口？ |
|---|---|---|
| `listen_port > 0` | 独占一个公网端口（frp 形态） | 否 |
| `host` + 可选 `path` | 共享 HTTP 端口上按 Host/Path 后缀路由 | 是 |
| `sni` | 共享 TLS 端口上按 SNI 直通（整字节流透传） | 是 |
| `access_token` | 访问器（fap-access）按 tunnel_id + token 接入 | 否（专用端口） |

路由优先级（已锁定）：**精确主机 > `*.{rest}` 通配**；同主机内**路径前缀最长者优先**；冲突整体失败不留半套状态。

## 6. 认证（conversational）

| 模式 | 命令行 | 状态 | 用途 |
|---|---|---|---|
| 旧明文 token | `--auth DEVICE:TOKEN` | 默认 | 开发测试，开源工具链 |
| HMAC-SHA256 | `--auth-hmac DEVICE:HEX_SECRET` | M2.5c | 中等部署 |
| Ed25519 PK | `--auth-pk DEVICE:HEX_PUBLIC_KEY` | M2.5d | 生产推荐 |

PK 流程（RustDesk 借鉴）：
1. agent 首帧 `PkRegister { hostname, os, arch, version, user, pk }`
2. gateway 校验：设备已登记公钥 → 挑战；未登记 → 直接 PK 注册节流（30s/次，失败 5 次锁 10 分钟）
3. 挑战：`AuthChallenge { nonce, ts }`
4. 应答：`AuthChallengeResp { ed25519_sig(nonce||ts) }`
5. 失败 5 次临时封禁 IP（CIDR 思路）。

## 7. 共享单端口（M3）

首包嗅探分流：
1. 看首字节是 `0x16`（TLS ClientHello）→ 解析 SNI → 路由查 sni_routes → 对应 tunnel
2. 看是否 `GET|POST|PUT|DELETE|HEAD|CONNECT|OPTIONS|PATCH` → 按 HTTP 解析 → route_http(host, path)
3. 解析私有协议首帧 `AccessRequest` → 访问器路由
4. 都不匹配 → 拒绝 + 审计「unknown NUDTP traffic」

控制台按 Host 反代：当请求 Host 命中 `console_host` 时，把请求代理到本机 Next.js 控制台（HTTP/1.1 转发，hop-by-hop 头清理）。

## 8. 管理面（M2 + M5）

admin API（axum）：
- `GET  /api/health` — 健康
- `GET  /api/devices` — 设备 + 在线状态 + 元信息 + 指标
- `GET  /api/devices/{id}/tunnels` — 控制台配置（来源：TunnelStore）
- `PUT  /api/devices/{id}/tunnels` — 覆盖配置并实时下发
- `GET  /api/devices/{id}/metrics` — 字节/流计数
- `GET  /api/audit?since=…` — 审计日志
- `POST /api/auth/login` — admin 登录挑战

auth（Bearer token），日志中 `MaskedString` 风格输出。

## 9. 指标与审计（M2.5b + M5a）

指标（每隧道）：
- `bytes_tx` / `bytes_rx` — 累计字节
- `active_streams` — 当前活跃流数
- `total_streams` — 累计开流数
- `last_error` — 最近错误（如内网服务拒绝连接）

存储：内存 `AtomicU64` + `parking_lot::RwLock` HashMap；admin API 读取。

审计：每条 admin 操作、注册/下线、配置下发、ACL 命中/拒绝都写一条 ring buffer + JSON Lines 文件。

## 10. 配置（TOML）

`fap-gateway.toml` / `fap-agent.toml`（参考 rathole/sozu）。

```toml
# gateway
control_addr  = "0.0.0.0:7100"
data_addr    = "0.0.0.0:7101"
shared_addr  = "0.0.0.0:443"
console_addr = "127.0.0.1:3000"
console_host = "console.fap.example"
admin_addr   = "0.0.0.0:7102"

[auth.device_token]
dev1 = "secret"

[auth.device_hmac]
dev2 = "00112233445566778899aabbccddeeff"

[auth.device_pk]
dev3 = "ed25519:abcdef..."
```

## 11. CLI（命令）

```bash
# 网关
fap-gateway --config gateway.toml

# 客户端
fap-agent --config agent.toml

# 访问器
fap-access --server gateway.example:443 --tunnel ssh --token abcdef

# 演示
fap-demo
```

## 12. 里程碑 → 提交

| 编号 | 内容 | 来源 |
|---|---|---|
| **M1** ✅ | 最小 TCP 穿透 | — |
| **M2** ✅ | 协议扩展 + admin API + 控制台覆盖 | — |
| **M3-路由表** ✅ | host/path/SNI/access 路由 | — |
| **M2.5a** | 设备元信息上报 | Orbien |
| **M2.5b** | 运行时指标 | Sozu |
| **M2.5c** | HMAC-SHA256 challenge-response | rathole/Orbien |
| **M2.5d** | Ed25519 PK 注册 + 30s 节流 | RustDesk |
| **M3a** | HTTP 解析器 + hop-by-hop 头清理 | hyper-reverse-proxy |
| **M3b** | SNI 解析器 | Cloudflare Pingora |
| **M3c** | shared_port 接线 + 控制台反代 + e2e | 整合 |
| **M3d** | toml 配置解析 | sozu/rathole |
| **M4a** | 访问器协议 e2e | — |
| **M4b** | fap-access 二进制 | Orbien |
| **M4c** | agent 本地管理页嵌入 | Tauri/VS Code |
| **M5a** | ACL/审计 + 限流 | pingora |
| **M5b** | admin API 鉴权强化（多用户、签名 token） | Orbien/RustDesk |
| **M5c** | 多路复用（yamux）+ 直连打洞可选 | rathole/RustDesk |
| **M6** | Next.js 控制台（Tailwind v4 + shadcn） | — |

## 13. 不做（明确排除）

- master/worker 主从（单进程足够）
- UDP 隧道（M5 不做，写入「未来规划」）
- WebRTC 数据通道（与本项目目标背离）
- Flutter/桌面 GUI（Web 控制台已规划）

## 15. 测试策略

- 单元测试（cargo test）：每个新行为先写失败测试
- wire format 锁定：protocol/tests/ 拒绝未覆盖的字段/消息
- e2e 测试（crates/gateway/tests/）：每个里程碑一两个 e2e 验收
- demo（crates/demo）：端到端跑通作为最终自检

## 14. 借鉴来源

| 项目 | 借鉴内容 |
|---|---|
| frp/nps | 数据面 + 控制面拆分、控制通道 / 数据通道分离 |
| rathole | 多路复用、传输层抽象（TCP/TLS/Noise/WS）、HMAC 挑战 |
| Orbien | 设备元信息、访问器、HTTP 隧道（domains/locations）、仪表盘 |
| sozu | master/worker、protobuf 命令协议、运行时配置、metrics |
| Cloudflare Pingora | `ProxyHttp` 钩子链、LB 算法、重试回调（我们用其心智） |
| hyper-reverse-proxy | hop-by-hop 头清理 |
| RustDesk | Ed25519 PK 注册 + 节流、port_forward_mux 多路复用、心跳教训 |