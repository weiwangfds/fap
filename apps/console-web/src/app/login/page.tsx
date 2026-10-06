"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, apiBase, getSession, clearSession } from "@/lib/api";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [base, setBase] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setBase(window.localStorage.getItem("fap_api_base") ?? "");
    // 已有会话则直接进入
    if (getSession()) router.replace("/");
  }, [router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      window.localStorage.setItem("fap_api_base", base);
      await api.login(token);
      router.replace("/");
    } catch (ex) {
      setErr(String(ex instanceof Error ? ex.message : ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">fap 控制台</CardTitle>
          <CardDescription>
            使用网关 admin 令牌登录；会话令牌短期有效，不落盘主令牌。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4" onSubmit={submit}>
            <label className="grid gap-2 text-sm">
              网关 API 地址（留空 = 同源）
              <Input
                value={base}
                onChange={(e) => setBase(e.target.value)}
                placeholder="https://gw.example.com"
              />
            </label>
            <label className="grid gap-2 text-sm">
              Admin 令牌
              <Input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="admin token"
                required
              />
            </label>
            {err && <p className="text-sm text-destructive">{err}</p>}
            <Button type="submit" disabled={busy}>
              {busy ? "登录中…" : "登录"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}

export { clearSession };
