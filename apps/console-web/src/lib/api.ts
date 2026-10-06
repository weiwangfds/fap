// fap admin API 客户端。
// API base 解析优先级：
//   1. localStorage.fap_api_base（登录页可改，指向远程网关）
//   2. NEXT_PUBLIC_FAP_API（构建时注入）
//   3. 同源相对路径（agent 内嵌场景：agent 在同一端口伺服页面与 /api）

export const SESSION_KEY = "fap_admin_session";

export function apiBase(): string {
  if (typeof window !== "undefined") {
    const stored = window.localStorage.getItem("fap_api_base");
    if (stored !== null && stored !== "") return stored.replace(/\/$/, "");
  }
  const env = process.env.NEXT_PUBLIC_FAP_API;
  if (env) return env.replace(/\/$/, "");
  return "";
}

export function getSession(): string | null {
  if (typeof window === "undefined") return null;
  return window.sessionStorage.getItem(SESSION_KEY);
}

export function setSession(s: string) {
  window.sessionStorage.setItem(SESSION_KEY, s);
}

export function clearSession() {
  window.sessionStorage.removeItem(SESSION_KEY);
}

async function req<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = {};
  const s = getSession();
  if (s) headers.Authorization = `Bearer ${s}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${apiBase()}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) {
    clearSession();
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

export interface DeviceInfo {
  hostname: string;
  os: string;
  arch: string;
  version: string;
  user: string;
}

export interface TunnelConfig {
  tunnel_id: string;
  listen_port: number;
  target_host: string;
  target_port: number;
  host?: string | null;
  path?: string | null;
  sni?: string | null;
  access_token?: string | null;
  allowed_ips: string[];
  max_concurrent?: number | null;
}

export interface Device {
  device_id: string;
  online: boolean;
  device_info: DeviceInfo | null;
  tunnels: TunnelConfig[];
}

export interface Metrics {
  bytes_tx: number;
  bytes_rx: number;
  active_streams: number;
  total_streams: number;
  last_error: string | null;
}

export interface AuditEvent {
  ts_ms: number;
  kind: string;
  subject: string;
  detail: string;
}

export const api = {
  async login(
    adminToken: string,
    ttlSecs = 8 * 3600
  ): Promise<{ session: string; expires_in_secs: number }> {
    const res = await fetch(`${apiBase()}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: adminToken, ttl_secs: ttlSecs }),
    });
    if (!res.ok) throw new Error(`登录失败：HTTP ${res.status}`);
    const v = (await res.json()) as { session: string; expires_in_secs: number };
    setSession(v.session);
    return v;
  },

  devices: (): Promise<{ devices: Device[] }> =>
    req("GET", "/api/devices"),

  getTunnels: (device: string): Promise<{ tunnels: TunnelConfig[] }> =>
    req("GET", `/api/devices/${encodeURIComponent(device)}/tunnels`),

  putTunnels: (
    device: string,
    tunnels: TunnelConfig[]
  ): Promise<{ ok: boolean; applied: boolean }> =>
    req("PUT", `/api/devices/${encodeURIComponent(device)}/tunnels`, tunnels),

  metrics: (device: string, tunnel: string): Promise<Metrics> =>
    req(
      "GET",
      `/api/devices/${encodeURIComponent(device)}/tunnels/${encodeURIComponent(tunnel)}/metrics`
    ),

  audit: (limit = 100): Promise<{ events: AuditEvent[] }> =>
    req("GET", `/api/audit?limit=${limit}`),
};
