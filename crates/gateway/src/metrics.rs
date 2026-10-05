//! 网关运行时指标：每隧道的 bytes_tx/bytes_rx/active_streams/total_streams/last_error。
//! 原子计数 — 锁内不得 await。

use std::collections::HashMap;
use std::sync::atomic::Ordering;

pub struct TunnelMetrics {
    bytes_tx: std::sync::atomic::AtomicU64,
    bytes_rx: std::sync::atomic::AtomicU64,
    active_streams: std::sync::atomic::AtomicU64,
    total_streams: std::sync::atomic::AtomicU64,
    /// 最近错误一次性写入：`Ordering::Release` 后 `Acquire` 读出 String；
    /// 内部用 `Mutex<String>` 是 Send 的——只要锁内不跨 await 即可。
    last_error: std::sync::Mutex<Option<String>>,
}

impl Default for TunnelMetrics {
    fn default() -> Self {
        Self {
            bytes_tx: std::sync::atomic::AtomicU64::new(0),
            bytes_rx: std::sync::atomic::AtomicU64::new(0),
            active_streams: std::sync::atomic::AtomicU64::new(0),
            total_streams: std::sync::atomic::AtomicU64::new(0),
            last_error: std::sync::Mutex::new(None),
        }
    }
}

impl TunnelMetrics {
    pub fn add_tx(&self, n: u64) {
        self.bytes_tx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_rx(&self, n: u64) {
        self.bytes_rx.fetch_add(n, Ordering::Relaxed);
    }
    pub fn open_stream(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        self.total_streams.fetch_add(1, Ordering::Relaxed);
    }
    pub fn close_stream(&self) {
        let _ = self.active_streams.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| if v == 0 { None } else { Some(v - 1) },
        );
    }
    pub fn set_last_error(&self, msg: String) {
        *self.last_error.lock().unwrap() = Some(msg);
    }
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            total_streams: self.total_streams.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MetricsSnapshot {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub active_streams: u64,
    pub total_streams: u64,
    pub last_error: Option<String>,
}

pub struct MetricsRegistry {
    by_tunnel: HashMap<(String, String), TunnelMetrics>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            by_tunnel: HashMap::new(),
        }
    }
}

impl MetricsRegistry {
    pub fn get_or_create(&mut self, device_id: &str, tunnel_id: &str) -> &TunnelMetrics {
        self.by_tunnel
            .entry((device_id.to_string(), tunnel_id.to_string()))
            .or_default()
    }

    pub fn snapshot(&self, device_id: &str, tunnel_id: &str) -> Option<MetricsSnapshot> {
        self.by_tunnel
            .get(&(device_id.to_string(), tunnel_id.to_string()))
            .map(|m| m.snapshot())
    }

    pub fn snapshot_all(&self) -> HashMap<(String, String), MetricsSnapshot> {
        self.by_tunnel
            .iter()
            .map(|(k, m)| (k.clone(), m.snapshot()))
            .collect()
    }

    /// 删除某设备的全部指标（设备下线 / 配置覆盖时清理）。
    pub fn remove_device(&mut self, device_id: &str) {
        self.by_tunnel.retain(|(d, _), _| d != device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_bytes_and_streams() {
        let mut r = MetricsRegistry::default();
        let m = r.get_or_create("dev1", "web");
        m.add_tx(100);
        m.add_tx(50);
        m.add_rx(75);
        m.open_stream();
        m.open_stream();
        m.close_stream();
        m.set_last_error("refused".into());
        let s = r.snapshot("dev1", "web").unwrap();
        assert_eq!(s.bytes_tx, 150);
        assert_eq!(s.bytes_rx, 75);
        assert_eq!(s.active_streams, 1);
        assert_eq!(s.total_streams, 2);
        assert_eq!(s.last_error.as_deref(), Some("refused"));
    }

    #[test]
    fn close_stream_never_underflows() {
        let mut r = MetricsRegistry::default();
        let m = r.get_or_create("dev1", "web");
        m.open_stream();
        m.close_stream();
        m.close_stream();
        assert_eq!(r.snapshot("dev1", "web").unwrap().active_streams, 0);
    }

    #[test]
    fn snapshot_unknown_returns_none() {
        let r = MetricsRegistry::default();
        assert!(r.snapshot("dev1", "ghost").is_none());
    }

    #[test]
    fn remove_device_clears_metrics() {
        let mut r = MetricsRegistry::default();
        r.get_or_create("dev1", "web").add_tx(10);
        r.get_or_create("dev1", "api").add_tx(20);
        r.get_or_create("dev2", "web").add_tx(30);
        r.remove_device("dev1");
        assert!(r.snapshot("dev1", "web").is_none());
        assert!(r.snapshot("dev1", "api").is_none());
        assert_eq!(r.snapshot("dev2", "web").unwrap().bytes_tx, 30);
    }

    #[test]
    fn snapshot_all_returns_each_tunnel() {
        let mut r = MetricsRegistry::default();
        r.get_or_create("dev1", "web").add_tx(1);
        r.get_or_create("dev1", "api").add_tx(2);
        r.get_or_create("dev2", "web").add_tx(3);
        let all = r.snapshot_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[&("dev1".into(), "web".into())].bytes_tx, 1);
    }
}