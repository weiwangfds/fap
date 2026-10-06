# fap — 可托管的开源内网穿透

fap 的目标是「frp 的数据面 + 向日葵式的托管体验」：

- **客户端零配置托管**：agent 装好即注册，设备状态集中可见；
- **控制台集中管理**：隧道规则在 Web 控制台配置、实时下发（M2）；
- **单端口多路复用**：对外只开一个端口，HTTP 按后缀/子域名路由，裸 TCP 走访问器协议（M3/M4）。

技术栈：**Rust**（gateway / agent 核心）+ **Next.js + TailwindCSS v4 + shadcn/ui**（控制台）。

## 当前进度

- [x] **M1** Rust 最小闭环：agent 注册 + 认证 + 心跳 + TCP 隧道 + 双向转发
- [x] **M2** admin API + 隧道规则实时下发（`GET/PUT /api/devices/{id}/tunnels`）
- [x] **M2.5** 设备元信息上报 / 每隧道流量指标 / HMAC-SHA256 挑战认证 / 注册节流
- [x] **M3** 单端口承诺：HTTP Host/Path + SNI 直通 + 控制台反代 + TOML 配置
- [x] **M4** 访问器协议（AccessRequest → 裸管道）+ `fap-access` 本地转发工具
- [x] **M4c** agent 内嵌本地管理页（rust-embed + `--local-ui 127.0.0.1:7800`）
- [x] **M5a** 审计日志 + ACL（`allowed_ips` CIDR）+ fail2ban 式节流
- [x] **M5b** admin 签名会话令牌（`POST /api/auth/login` 换短期会话，主令牌不落浏览器）
- [x] **M6** Next.js + Tailwind v4 + shadcn 控制台（静态导出，登录/设备/隧道编辑/指标/审计）
- [ ] **M5c** yamux 多路复用（StreamConn 首帧声明流 ID 的设计已是复用前置，接入点见 `DESIGN.md`）/ 数据连接池预热 / 直连打洞

## 快速上手（单二进制体验，向日葵式）

```bash
# 1. 构建控制台静态页（一次）
cd apps/console-web && npm install && npm run build && cd ../..

# 2. 网关（公网机器）+ 客户端（内网机器，带本地管理页）
cargo run -p fap-gateway -- --auth dev1:secret --shared-addr 0.0.0.0:443
cargo run -p fap-agent -- --device-id dev1 --token secret \
    --tunnel web:0:127.0.0.1:8080 --local-ui 127.0.0.1:7800
# 打开 http://127.0.0.1:7800 —— 本机状态 + 内嵌控制台
```

## 安全模型

| 模式 | 配置 | 说明 |
|---|---|---|
| 明文 token | `[auth] dev = "secret"` | 开发用 |
| HMAC-SHA256 | `[auth_hmac] dev = "<64位hex>"` | 挑战响应，120s 时钟窗口，常量时间比较 |
| 节流 | 自动 | fail2ban 语义：正确凭证总放行，连续 5 次失败封禁 10 分钟 |
| ACL | 隧道 `allowed_ips = ["10.0.0.0/8"]` | 空表不限，CIDR 匹配，拒绝入审计 |

## 快速开始

```bash
# 一条命令看完整链路（进程内拉起 echo + 网关 + 客户端 + 模拟用户）
cargo run -p fap-demo

# 手动运行（两个终端）
cargo run -p fap-gateway -- --auth dev1:secret
cargo run -p fap-agent -- --device-id dev1 --token secret \
    --tunnel web:7200:127.0.0.1:8080     # 把内网 8080 暴露到网关的 7200
```

`--tunnel` 规格为 `NAME:PORT:TARGET_HOST:TARGET_PORT`，`PORT` 填 `0` 由网关自动分配。

## 测试（TDD）

本项目全程测试先行：单元测试定义模块契约，端到端测试作为里程碑验收。

```bash
cargo test          # 44 个测试（codec / 注册表 / 路由 / 流匹配 / e2e）
cargo clippy --workspace
```

e2e 覆盖：双向转发、并发不串流、1MB 分块传输、错误令牌拒绝且网关不受影响。

## 架构

```
用户 ──▶ 网关隧道端口 ──▶ (OpenStream) ──▶ agent ──▶ 内网服务
              ▲                                   │
              └──────── (StreamConn 数据连接) ─────┘

控制连接：Register / RegisterAck / Heartbeat / HeartbeatAck / OpenStream
数据连接：首帧 StreamConn 声明流 ID，其后为裸字节流
```

- `crates/protocol` — 消息定义与帧编解码（`[u32 BE 长度][类型 u8][JSON]`）
- `crates/gateway` — 网关：设备注册表、隧道路由、流匹配、监听与转发
- `crates/agent` — 客户端：会话、心跳、指数退避重连、开流处理
- `crates/demo` — 端到端演示
- `apps/console` — Next.js 控制台（M2）

## 已知简化（M1）

- 控制通道为明文 TCP（TLS 在 M3 随单端口路由一起引入）；
- 被顶替的旧控制连接靠自身超时退出，未主动断开；
- 优雅停机未覆盖每条隧道的监听任务，进程退出时随运行时回收。

## 开发约定

- 任何新行为先写失败测试，再写实现；
- 帧格式或消息结构变更必须同步更新 `crates/protocol/tests/`（wire format 锁定测试）；
- `std::sync::Mutex` 保护的核心状态锁内禁止 `.await`。
