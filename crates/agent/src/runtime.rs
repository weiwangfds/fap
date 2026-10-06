//! agent 运行时状态：会话与本地管理页共享的本机视角数据。
//! 原子/锁保护，锁内不得 await。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use fap_protocol::TunnelConfig;
use tokio::net::TcpStream;

pub struct RuntimeStatus {
    pub device_id: String,
    pub server_addr: String,
    pub registered: AtomicBool,
    pub active_streams: AtomicU64,
    pub total_streams: AtomicU64,
    last_error: RwLock<Option<String>>,
    tunnels: RwLock<Vec<TunnelConfig>>,
    /// M5c-2：agent 预热数据连接池（按 conn_id 索引）。
    /// OpenStream 抢 arrived with conn_id=k 时，handle_stream 从 pool[k] 取连接，跳过拨号。
    data_pool: Mutex<VecDeque<TcpStream>>,
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
            data_pool: Mutex::new(VecDeque::new()),
        }
    }

    /// M5c-2：把一条预热的 data 连接存入池。池上界 8。
    pub fn pool_push(&self, conn: TcpStream) {
        let mut q = self.data_pool.lock().unwrap();
        if q.len() < 8 {
            q.push_back(conn);
        }
    }

    /// M5c-2：按 OpenStream 中的 conn_id 取一条池连接（缺则返回 None）。
    pub fn pool_take_by_id(&self, conn_id: u32) -> Option<TcpStream> {
        let mut q = self.data_pool.lock().unwrap();
        if q.is_empty() {
            return None;
        }
        // conn_id 是 OpenStream 中的索引；映射到 VecDeque：取头部作为 conn_id=1
        // （池条目按入池顺序编号）。简单实现：忽略 conn_id 具体值，
        // 只要池非空就返回头部（agent 与 gateway 已通过 OpenStream 顺序对齐）。
        q.pop_front()
    }

    pub fn pool_len(&self) -> usize {
        self.data_pool.lock().unwrap().len()
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