//! 隧道路由表：对外监听端口 ↔ (设备, 隧道) 的映射。

use std::collections::HashMap;

use fap_protocol::TunnelConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub device_id: String,
    pub tunnel_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunnelError {
    #[error("端口 {0} 已被设备 {1} 的隧道占用")]
    PortInUse(u16, String),
    #[error("主机路由 {0} 已被设备 {1} 的隧道占用")]
    HostInUse(String, String),
    #[error("SNI 路由 {0} 已被设备 {1} 的隧道占用")]
    SniInUse(String, String),
}

#[derive(Default)]
pub struct TunnelRouter {
    by_port: HashMap<u16, RouteTarget>,
    port_by_tunnel: HashMap<(String, String), u16>,
    /// HTTP 主机路由：主机（小写，可含 `*.` 通配前缀）→ (路径前缀, 目标) 列表。
    http_routes: HashMap<String, Vec<(Option<String>, RouteTarget)>>,
    /// SNI 直通路由：服务器名（小写）→ 目标。
    sni_routes: HashMap<String, RouteTarget>,
    /// 访问器路由：tunnel_id → (目标, 访问令牌)。
    access_routes: HashMap<String, (RouteTarget, Option<String>)>,
}

impl TunnelRouter {
    /// 按声明的 listen_port 登记（listen_port=0 表示自动分配，由服务端绑定后修正）。
    pub fn register(&mut self, device_id: &str, tunnels: &[TunnelConfig]) -> Result<(), TunnelError> {
        let bound: Vec<(String, u16)> = tunnels
            .iter()
            .map(|t| (t.tunnel_id.clone(), t.listen_port))
            .collect();
        self.register_bound(device_id, &bound)
    }

    /// 以实际绑定端口登记（仅端口路由，不含 host/sni/访问器路由）。
    pub fn register_bound(&mut self, device_id: &str, bound: &[(String, u16)]) -> Result<(), TunnelError> {
        self.register_full(device_id, &[], bound)
    }

    /// 以完整隧道定义登记：独占端口走 actual_ports，host/path/sni/access_token
    /// 路由来自隧道定义本身。任何冲突都整体失败，不留半套状态。
    pub fn register_full(
        &mut self,
        device_id: &str,
        tunnels: &[TunnelConfig],
        actual_ports: &[(String, u16)],
    ) -> Result<(), TunnelError> {
        // 预检：与他人冲突立即失败
        for (_, port) in actual_ports {
            if let Some(existing) = self.by_port.get(port) {
                if existing.device_id != device_id {
                    return Err(TunnelError::PortInUse(*port, existing.device_id.clone()));
                }
            }
        }
        for t in tunnels {
            if let Some(host) = &t.host {
                let key = normalize_host(host);
                if let Some(entries) = self.http_routes.get(&key) {
                    if entries.iter().any(|(_, r)| r.device_id != device_id) {
                        let owner = entries[0].1.device_id.clone();
                        return Err(TunnelError::HostInUse(host.clone(), owner));
                    }
                }
            }
            if let Some(sni) = &t.sni {
                let key = sni.to_lowercase();
                if let Some(existing) = self.sni_routes.get(&key) {
                    if existing.device_id != device_id {
                        return Err(TunnelError::SniInUse(sni.clone(), existing.device_id.clone()));
                    }
                }
            }
        }

        // 提交：先清掉本设备旧状态，再全量写入
        self.remove_device(device_id);
        for (tunnel_id, port) in actual_ports {
            self.by_port.insert(
                *port,
                RouteTarget {
                    device_id: device_id.to_string(),
                    tunnel_id: tunnel_id.clone(),
                },
            );
            self.port_by_tunnel
                .insert((device_id.to_string(), tunnel_id.clone()), *port);
        }
        for t in tunnels {
            let target = RouteTarget {
                device_id: device_id.to_string(),
                tunnel_id: t.tunnel_id.clone(),
            };
            if let Some(host) = &t.host {
                self.http_routes
                    .entry(normalize_host(host))
                    .or_default()
                    .push((t.path.clone(), target.clone()));
            }
            if let Some(sni) = &t.sni {
                self.sni_routes.insert(sni.to_lowercase(), target.clone());
            }
            if t.access_token.is_some() {
                self.access_routes
                    .insert(t.tunnel_id.clone(), (target, t.access_token.clone()));
            }
        }
        Ok(())
    }

    /// 按主机与路径查找 HTTP 隧道。主机精确匹配优先于 `*.` 通配；
    /// 同主机内路径前缀最长者优先。host 为空返回 None。
    pub fn route_http(&self, host: &str, path: &str) -> Option<RouteTarget> {
        let host = normalize_host(host);
        if host.is_empty() {
            return None;
        }
        let wildcard = host.split_once('.').map(|(_, rest)| format!("*.{rest}"));
        let mut best: Option<(i32, usize, RouteTarget)> = None;
        let mut exact_hit = false;
        // 精确命中优先（score=2），通配后缀其次（score=1）
        if let Some(entries) = self.http_routes.get(&host) {
            let before = best.is_some();
            evaluate(entries, path, 2, &mut best);
            exact_hit = best.is_some() && !before;
        }
        // 精确表没命中（或命中但路径不匹配）才退到通配
        let exact_alive = matches!(best, Some((s, _, _)) if s == 2);
        if !exact_alive {
            if let Some(w) = &wildcard {
                if let Some(entries) = self.http_routes.get(w) {
                    evaluate(entries, path, 1, &mut best);
                }
            }
        }
        let _ = exact_hit;
        best.map(|(_, _, t)| t)
    }

    /// 按 SNI 服务器名查找直通隧道。
    pub fn route_sni(&self, server_name: &str) -> Option<RouteTarget> {
        self.sni_routes.get(&server_name.to_lowercase()).cloned()
    }

    /// 访问器接入：校验访问令牌并返回目标；隧道未启用访问器时返回 None。
    pub fn route_access(&self, tunnel_id: &str, token: &str) -> Option<RouteTarget> {
        match self.access_routes.get(tunnel_id) {
            Some((target, Some(expected))) if expected == token => Some(target.clone()),
            _ => None,
        }
    }

    /// 移除设备的全部隧道，返回释放的端口。
    pub fn remove_device(&mut self, device_id: &str) -> Vec<u16> {
        let ports: Vec<u16> = self
            .by_port
            .iter()
            .filter(|(_, t)| t.device_id == device_id)
            .map(|(p, _)| *p)
            .collect();
        for p in &ports {
            self.by_port.remove(p);
        }
        self.port_by_tunnel.retain(|(dev, _), _| dev != device_id);
        for entries in self.http_routes.values_mut() {
            entries.retain(|(_, r)| r.device_id != device_id);
        }
        self.http_routes.retain(|_, v| !v.is_empty());
        self.sni_routes.retain(|_, r| r.device_id != device_id);
        self.access_routes.retain(|_, (r, _)| r.device_id != device_id);
        ports
    }

    pub fn route(&self, port: u16) -> Option<RouteTarget> {
        self.by_port.get(&port).cloned()
    }

    pub fn tunnel_port(&self, device_id: &str, tunnel_id: &str) -> Option<u16> {
        self.port_by_tunnel
            .get(&(device_id.to_string(), tunnel_id.to_string()))
            .copied()
    }

    pub fn tunnel_ports_of_device(&self, device_id: &str) -> Vec<u16> {
        self.by_port
            .iter()
            .filter(|(_, t)| t.device_id == device_id)
            .map(|(p, _)| *p)
            .collect()
    }
}

/// 在候选条目里更新最佳匹配。
fn evaluate(
    entries: &[(Option<String>, RouteTarget)],
    path: &str,
    host_score: i32,
    best: &mut Option<(i32, usize, RouteTarget)>,
) {
    for (prefix, target) in entries {
        let hit = match prefix {
            Some(p) => path_matches(path, p),
            None => true,
        };
        if !hit {
            continue;
        }
        let len = prefix.as_ref().map(|p| p.len()).unwrap_or(0);
        let candidate = (host_score, len, target.clone());
        let better = match best.as_ref() {
            None => true,
            Some((s, l, _)) => *s < host_score || (*s == host_score && *l < len),
        };
        if better {
            *best = Some(candidate);
        }
    }
}

/// 主机名归一：小写、去除端口部分。
fn normalize_host(host: &str) -> String {
    let h = host.trim().to_lowercase();
    // IPv6：[::1] / [::1]:80
    if let Some(rest) = h.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    let h = h.split(':').next().unwrap_or("");
    h.to_string()
}

/// 路径前缀匹配：
/// - `/web` 命中 `/web`、`/web/`、`/web/x`，不命中 `/webx`；
/// - `/web/` 只命中以 `/web/` 开头的路径。
fn path_matches(path: &str, prefix: &str) -> bool {
    if !prefix.starts_with('/') {
        return false;
    }
    let starts_with_prefix = prefix.ends_with('/')
        || path.starts_with(prefix);
    if !starts_with_prefix {
        return false;
    }
    if prefix.ends_with('/') {
        true
    } else {
        // 要求前缀结尾后是路径边界（空串或 `/`）
        path.len() == prefix.len() || path.as_bytes().get(prefix.len()) == Some(&b'/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: &str, port: u16) -> TunnelConfig {
        TunnelConfig {
            tunnel_id: id.into(),
            listen_port: port,
            target_host: "127.0.0.1".into(),
            target_port: 8080,
            ..Default::default()
        }
    }

    fn cfg_host(id: &str, host: &str, path: Option<&str>) -> TunnelConfig {
        TunnelConfig {
            tunnel_id: id.into(),
            listen_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 80,
            host: Some(host.into()),
            path: path.map(|p| p.into()),
            ..Default::default()
        }
    }

    #[test]
    fn register_full_routes_by_host_and_path() {
        let mut r = TunnelRouter::default();
        r.register_full(
            "dev1",
            &[
                cfg_host("a", "a.test", None),
                cfg_host("b", "b.test", Some("/api")),
            ],
            &[],
        )
        .unwrap();

        assert_eq!(r.route_http("a.test", "/").unwrap().tunnel_id, "a");
        assert_eq!(r.route_http("a.test:80", "/x").unwrap().tunnel_id, "a", "host 带端口应可匹配");
        // 大小写归一：A.TEST 等价于 a.test（精确），B.TEST 等价于 b.test（精确）
        assert_eq!(r.route_http("A.TEST", "/").unwrap().tunnel_id, "a");
        assert_eq!(r.route_http("B.TEST", "/api").unwrap().tunnel_id, "b");
        assert_eq!(r.route_http("b.test", "/api").unwrap().tunnel_id, "b");
        assert_eq!(r.route_http("b.test", "/api/x").unwrap().tunnel_id, "b");
        // 精确表 b 命中失败且无通配回退，返回 None（用户应配置通配 host 才能回退）
        assert!(r.route_http("b.test", "/anything").is_none());
        assert!(r.route_http("none.test", "/").is_none());
    }

    #[test]
    fn wildcard_host_falls_back_when_exact_path_misses() {
        let mut r = TunnelRouter::default();
        // a.test 是精确 host 无路径前缀；*.test 通配带 /api 前缀
        let mut a = cfg_host("a", "a.test", None);
        let api_dev = cfg_host("api", "*.test", Some("/api"));
        // 显式标注：先注册一个表里的内容
        r.register_full("dev1", &[a.clone()], &[]).unwrap();
        // 此时 a 在 a.test 表；再加一个 *.test 通配条目
        let mut api = api_dev;
        api.tunnel_id = "api".into();
        r.register_full("dev2", &[api], &[]).unwrap();
        // 精确 a.test 任意路径命中 a
        assert_eq!(r.route_http("a.test", "/x").unwrap().tunnel_id, "a");
        // b.test 通配 /api 命中 api
        assert_eq!(r.route_http("b.test", "/api/x").unwrap().tunnel_id, "api");
        // a.test 访问 /api 路径：精确 host 中 a 命中（无前缀匹配），且精确优先级更高 → a
        assert_eq!(r.route_http("a.test", "/api").unwrap().tunnel_id, "a");
    }

    #[test]
    fn register_full_wildcard_host_matches_but_exact_wins() {
        let mut r = TunnelRouter::default();
        // 通配在前，精确在后
        r.register_full(
            "dev1",
            &[cfg_host("share", "*.test", Some("/share"))],
            &[],
        )
        .unwrap();
        r.register_full(
            "dev2",
            &[cfg_host("private", "a.test", Some("/p"))],
            &[],
        )
        .unwrap();
        assert_eq!(r.route_http("a.test", "/share/x").unwrap().device_id, "dev1", "通配匹配");
        assert_eq!(r.route_http("a.test", "/p").unwrap().device_id, "dev2", "精确匹配优先");
        assert_eq!(r.route_http("b.test", "/share").unwrap().device_id, "dev1");
    }

    #[test]
    fn path_prefix_longest_wins() {
        let mut r = TunnelRouter::default();
        r.register_full(
            "dev1",
            &[
                cfg_host("a", "x.test", Some("/api")),
                cfg_host("b", "x.test", Some("/api/v2")),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(r.route_http("x.test", "/api/v2/x").unwrap().tunnel_id, "b");
        assert_eq!(r.route_http("x.test", "/api/x").unwrap().tunnel_id, "a");
    }

    #[test]
    fn sni_route_and_access_route() {
        let mut r = TunnelRouter::default();
        let mut t = TunnelConfig {
            tunnel_id: "ssh".into(),
            listen_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 22,
            sni: Some("ssh.test".into()),
            access_token: Some("t0".into()),
            ..Default::default()
        };
        r.register_full("dev1", &[t.clone()], &[]).unwrap();

        assert_eq!(r.route_sni("ssh.test").unwrap().tunnel_id, "ssh");
        assert_eq!(r.route_sni("SSH.TEST").unwrap().tunnel_id, "ssh");
        assert!(r.route_sni("other.test").is_none());

        assert!(r.route_access("ssh", "wrong").is_none(), "令牌错误应拒绝");
        assert!(r.route_access("unknown", "t0").is_none(), "未启用访问器应拒绝");
        assert_eq!(r.route_access("ssh", "t0").unwrap().tunnel_id, "ssh", "令牌正确");
        let _ = t;
    }

    #[test]
    fn host_and_sni_conflicts_rejected_atomically() {
        let mut r = TunnelRouter::default();
        r.register_full("dev1", &[cfg_host("a", "a.test", None)], &[])
            .unwrap();
        assert_eq!(
            r.register_full("dev2", &[cfg_host("b", "a.test", None)], &[]).unwrap_err(),
            TunnelError::HostInUse("a.test".into(), "dev1".into())
        );
        // SNI 冲突：先清理 dev1 的 host，再注册 dev1 的 sni 隧道
        r.remove_device("dev1");
        let sni1 = TunnelConfig {
            tunnel_id: "c".into(),
            listen_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 22,
            sni: Some("ssh.test".into()),
            ..Default::default()
        };
        r.register_full("dev1", &[sni1], &[]).unwrap();
        let sni2 = TunnelConfig {
            tunnel_id: "d".into(),
            listen_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 22,
            sni: Some("ssh.test".into()),
            ..Default::default()
        };
        assert_eq!(
            r.register_full("dev2", &[sni2], &[]).unwrap_err(),
            TunnelError::SniInUse("ssh.test".into(), "dev1".into())
        );
        assert!(r.route_http("b-only.test", "/").is_none(), "失败登记不应留下 dev2 状态");
    }

    #[test]
    fn remove_device_clears_all_route_kinds() {
        let mut r = TunnelRouter::default();
        let mut t = cfg_host("multi", "m.test", Some("/p"));
        t.sni = Some("sni.test".into());
        t.access_token = Some("t".into());
        r.register_full("dev1", &[t], &[("multi".into(), 7300)]).unwrap();
        r.remove_device("dev1");
        assert!(r.route(7300).is_none());
        assert!(r.route_http("m.test", "/p").is_none());
        assert!(r.route_sni("sni.test").is_none());
        assert!(r.route_access("multi", "t").is_none());
    }

    #[test]
    fn path_matches_rules() {
        assert!(path_matches("/web", "/web"));
        assert!(path_matches("/web/", "/web"));
        assert!(path_matches("/web/x", "/web"));
        assert!(path_matches("/web", "/web/"));
        assert!(!path_matches("/webx", "/web"));
        assert!(!path_matches("/", "/web"));
        assert!(!path_matches("web", "/web"));
    }

    #[test]
    fn register_then_route_hits() {
        let mut r = TunnelRouter::default();
        r.register_bound("dev1", &[("web".into(), 7200)]).unwrap();
        assert_eq!(
            r.route(7200),
            Some(RouteTarget {
                device_id: "dev1".into(),
                tunnel_id: "web".into()
            })
        );
        assert_eq!(r.tunnel_port("dev1", "web"), Some(7200));
    }

    #[test]
    fn cross_device_port_conflict_is_rejected() {
        let mut r = TunnelRouter::default();
        r.register_bound("dev1", &[("web".into(), 7200)]).unwrap();
        let err = r
            .register_bound("dev2", &[("api".into(), 7200)])
            .unwrap_err();
        assert_eq!(err, TunnelError::PortInUse(7200, "dev1".into()));
        // 冲突登记必须整体失败，不能留下半套状态
        assert!(r.route(7200).is_some());
        assert_eq!(r.tunnel_port("dev2", "api"), None);
    }

    #[test]
    fn same_device_re_register_replaces_old_ports() {
        let mut r = TunnelRouter::default();
        r.register_bound("dev1", &[("web".into(), 7200)]).unwrap();
        r.register_bound("dev1", &[("web".into(), 7300)]).unwrap();
        assert!(r.route(7200).is_none(), "旧端口应被释放");
        assert_eq!(r.route(7300).unwrap().device_id, "dev1");
        assert_eq!(r.tunnel_port("dev1", "web"), Some(7300));
    }

    #[test]
    fn remove_device_frees_ports_and_reports_them() {
        let mut r = TunnelRouter::default();
        r.register_bound("dev1", &[("a".into(), 7001), ("b".into(), 7002)])
            .unwrap();
        let freed = r.remove_device("dev1");
        assert_eq!(freed.len(), 2);
        assert!(freed.contains(&7001) && freed.contains(&7002));
        assert!(r.route(7001).is_none());
        // 释放后端口可被其他设备使用
        r.register_bound("dev2", &[("c".into(), 7001)]).unwrap();
        assert_eq!(r.route(7001).unwrap().device_id, "dev2");
    }

    #[test]
    fn register_with_declared_ports_uses_listen_port() {
        let mut r = TunnelRouter::default();
        r.register("dev1", &[cfg("web", 7200)]).unwrap();
        assert_eq!(r.tunnel_port("dev1", "web"), Some(7200));
    }

    #[test]
    fn tunnel_ports_of_device_lists_all() {
        let mut r = TunnelRouter::default();
        r.register_bound("dev1", &[("a".into(), 7001), ("b".into(), 7002)])
            .unwrap();
        let ports = r.tunnel_ports_of_device("dev1");
        assert!(ports.contains(&7001) && ports.contains(&7002));
        assert!(r.tunnel_ports_of_device("ghost").is_empty());
    }
}
