//! agent 运行时状态：会话与本地管理页共享的本机视角数据。
//! 原子/锁保护，锁内不得 await。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

use fap_protocol::TunnelConfig;

pub struct RuntimeStatus {
    pub device_id: String,
    pub server_addr: String,
    pub registered: AtomicBool,
    pub active_streams: AtomicU64,
    pub total_streams: AtomicU64,
    last_error: RwLock<Option<String>>,
    tunnels: RwLock<Vec<TunnelConfig>>,
}

impl RuntimeStatus {
    pub fn new(device_id: &str, server_addr: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            server_addr: server_addr.to_string(),
            registered: AtomicBool::new(false),
            active_streams: AtomicU64::new(0),
            total_streams: AtomicU64::new(0),
            last_error: RwLock::new(None),
            tunnels: RwLock::new(Vec::new()),
        }
    }

    pub fn set_registered(&self, v: bool) {
        self.registered.store(v, Ordering::Relaxed);
    }

    pub fn set_tunnels(&self, tunnels: Vec<TunnelConfig>) {
        *self.tunnels.write().unwrap() = tunnels;
    }

    pub fn tunnels_read(&self) -> Vec<TunnelConfig> {
        self.tunnels.read().unwrap().clone()
    }

    pub fn set_last_error(&self, msg: String) {
        *self.last_error.write().unwrap() = Some(msg);
    }

    pub fn set_last_error_clear(&self) {
        *self.last_error.write().unwrap() = None;
    }

    pub fn last_error_snapshot(&self) -> Option<String> {
        self.last_error.read().unwrap().clone()
    }

    pub fn stream_opened(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        self.total_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_closed(&self) {
        let _ = self.active_streams.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |v| if v == 0 { None } else { Some(v - 1) },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_never_underflow_and_tunnels_roundtrip() {
        let st = RuntimeStatus::new("d", "s");
        st.set_registered(true);
        st.stream_opened();
        st.stream_closed();
        st.stream_closed(); // 不下溢
        assert_eq!(st.active_streams.load(Ordering::Relaxed), 0);
        assert_eq!(st.total_streams.load(Ordering::Relaxed), 1);
        st.set_tunnels(vec![TunnelConfig {
            tunnel_id: "web".into(),
            ..Default::default()
        }]);
        assert_eq!(st.tunnels_read().len(), 1);
        st.set_last_error("x".into());
        assert_eq!(st.last_error_snapshot().as_deref(), Some("x"));
    }
}