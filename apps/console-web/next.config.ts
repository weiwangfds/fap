import type { NextConfig } from "next";

// 静态导出：产物可被 fap-agent 用 rust-embed 内嵌（M4c），
// 也可由网关按 Host 反代到 `next start` 进程（服务端部署形态）。
// API 地址运行时解析见 src/lib/api.ts：agent 内嵌场景用同源相对路径。
const nextConfig: NextConfig = {
  output: "export",
};

export default nextConfig;
