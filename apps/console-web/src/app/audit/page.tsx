"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api, clearSession, getSession, type AuditEvent } from "@/lib/api";

function fmtTime(tsMs: number): string {
  return new Date(tsMs).toLocaleString();
}

export default function AuditPage() {
  const router = useRouter();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!getSession()) {
      router.replace("/login");
      return;
    }
    api
      .audit(200)
      .then((v) => setEvents(v.events))
      .catch((ex) => {
        const msg = String(ex instanceof Error ? ex.message : ex);
        if (msg === "unauthorized") {
          clearSession();
          router.replace("/login");
          return;
        }
        setErr(msg);
      });
  }, [router]);

  return (
    <main className="mx-auto max-w-5xl p-6">
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">审计日志</h1>
        <Button variant="outline" onClick={() => router.push("/")}>
          返回设备
        </Button>
      </header>

      {err && (
        <p className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {err}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>最近事件（新→旧，最多 200 条）</CardTitle>
          <CardDescription>
            注册成功/失败、访问拒绝、管理员登录等均在此留痕。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>类别</TableHead>
                <TableHead>主体</TableHead>
                <TableHead>详情</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((e, i) => (
                <TableRow key={i}>
                  <TableCell className="whitespace-nowrap">
                    {fmtTime(e.ts_ms)}
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-xs">{e.kind}</span>
                  </TableCell>
                  <TableCell>{e.subject}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {e.detail}
                  </TableCell>
                </TableRow>
              ))}
              {events.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    暂无事件
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </main>
  );
}
