"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import {
  api,
  clearSession,
  getSession,
  type Device,
  type Metrics,
  type TunnelConfig,
} from "@/lib/api";

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function tunnelExposure(t: TunnelConfig): string {
  if (t.listen_port > 0) return `端口 ${t.listen_port}`;
  const parts: string[] = [];
  if (t.host) parts.push(t.host + (t.path ?? ""));
  if (t.sni) parts.push(`SNI:${t.sni}`);
  if (t.access_token) parts.push("访问器");
  return parts.join(" / ") || "—";
}

export default function Dashboard() {
  const router = useRouter();
  const [devices, setDevices] = useState<Device[]>([]);
  const [metrics, setMetrics] = useState<Record<string, Metrics>>({});
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");

  const load = useCallback(async () => {
    try {
      const v = await api.devices();
      setDevices(v.devices);
      setErr(null);
      const next: Record<string, Metrics> = {};
      for (const d of v.devices) {
        for (const t of d.tunnels) {
          try {
            next[`${d.device_id}/${t.tunnel_id}`] = await api.metrics(
              d.device_id,
              t.tunnel_id
            );
          } catch {
            /* 无流量的隧道返回 404，忽略 */
          }
        }
      }
      setMetrics(next);
    } catch (ex) {
      const msg = String(ex instanceof Error ? ex.message : ex);
      if (msg === "unauthorized") {
        clearSession();
        router.replace("/login");
        return;
      }
      setErr(msg);
    }
  }, [router]);

  useEffect(() => {
    if (!getSession()) {
      router.replace("/login");
      return;
    }
    load();
    const tk = setInterval(load, 5000);
    return () => clearInterval(tk);
  }, [load, router]);

  async function saveTunnels(device: string) {
    try {
      const parsed = JSON.parse(draft) as TunnelConfig[];
      await api.putTunnels(device, parsed);
      setEditing(null);
      await load();
    } catch (ex) {
      setErr(String(ex instanceof Error ? ex.message : ex));
    }
  }

  return (
    <main className="mx-auto max-w-6xl p-6">
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">fap 控制台</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => router.push("/audit")}>
            审计日志
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              clearSession();
              router.replace("/login");
            }}
          >
            退出
          </Button>
        </div>
      </header>

      {err && (
        <p className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}

      {devices.length === 0 && !err && (
        <Card>
          <CardHeader>
            <CardTitle>暂无设备</CardTitle>
            <CardDescription>
              在内网机器上运行 fap-agent 并指向本网关即可出现在这里。
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <div className="grid gap-6">
        {devices.map((d) => (
          <Card key={d.device_id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    {d.device_id}
                    <Badge variant={d.online ? "default" : "secondary"}>
                      {d.online ? "在线" : "离线"}
                    </Badge>
                  </CardTitle>
                  <CardDescription>
                    {d.device_info
                      ? [
                          d.device_info.hostname,
                          d.device_info.os,
                          d.device_info.arch,
                          `v${d.device_info.version}`,
                          d.device_info.user && `@${d.device_info.user}`,
                        ]
                          .filter(Boolean)
                          .join(" · ")
                      : "无元信息"}
                  </CardDescription>
                </div>
                <Button
                  variant="outline"
                  onClick={() => {
                    if (editing === d.device_id) {
                      setEditing(null);
                    } else {
                      setDraft(JSON.stringify(d.tunnels, null, 2));
                      setEditing(d.device_id);
                    }
                  }}
                >
                  {editing === d.device_id ? "取消" : "编辑隧道"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>隧道</TableHead>
                    <TableHead>暴露方式</TableHead>
                    <TableHead>内网目标</TableHead>
                    <TableHead className="text-right">↓ 接收</TableHead>
                    <TableHead className="text-right">↑ 发送</TableHead>
                    <TableHead className="text-right">活跃/累计流</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.tunnels.map((t) => {
                    const m = metrics[`${d.device_id}/${t.tunnel_id}`];
                    return (
                      <TableRow key={t.tunnel_id}>
                        <TableCell className="font-medium">
                          {t.tunnel_id}
                        </TableCell>
                        <TableCell>{tunnelExposure(t)}</TableCell>
                        <TableCell>
                          {t.target_host}:{t.target_port}
                        </TableCell>
                        <TableCell className="text-right">
                          {m ? humanBytes(m.bytes_rx) : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          {m ? humanBytes(m.bytes_tx) : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          {m ? `${m.active_streams} / ${m.total_streams}` : "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                  {d.tunnels.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-muted-foreground">
                        无隧道
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              {editing === d.device_id && (
                <>
                  <Separator className="my-4" />
                  <p className="mb-2 text-sm text-muted-foreground">
                    编辑 JSON 隧道数组（保存即整体覆盖并热下发到设备）：
                  </p>
                  <Input
                    className="min-h-40 font-mono text-xs"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                  />
                  <div className="mt-2 flex gap-2">
                    <Button onClick={() => saveTunnels(d.device_id)}>
                      保存并下发
                    </Button>
                    <Button variant="ghost" onClick={() => setEditing(null)}>
                      取消
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </main>
  );
}
