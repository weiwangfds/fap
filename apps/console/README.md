# fap console（M2 里程碑）

Web 管理控制台：设备列表（在线状态/心跳/版本）、隧道规则编辑、访问器管理、操作审计。

## 技术栈（已确定）

- Next.js（App Router）
- TailwindCSS v4
- shadcn/ui
- Route Handlers 作为 BFF，转发到 gateway 的 admin API（Rust 是运行时唯一事实源）

## 形态

- 服务端控制台：独立进程，由 Rust 网关按 SNI/路径反代到本机；
- agent 本地管理页：`next build`（`output: 'export'`）静态导出，经 `rust-embed`
  打进 agent 二进制，由 Rust 在 `127.0.0.1` 伺服——单文件分发，与桌面端组件复用。

M1 已完成 Rust 核心闭环（注册/心跳/TCP 隧道/双向转发），M2 在此目录初始化项目。
