//! 数据连接池：预热的 agent 数据连接缓冲。
//!
//! agent 启动时预建立 N 条 data 端口连接到网关侧（见 M5c-2 agent 端预连接）；
//! 连接 idle 状态下挂在本池；OpenStream 时取出一条活跃连接直接分发，
//! 消除「OpenStream → agent 拨号 data 端口 → 发送 StreamConn」的用户态延迟。
//!
//! 当 M5c-2 未开启（agent 不预热）时，池为空，原数据面路径不变。

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::net::TcpStream;

/// 数据连接池：预热的 agent 数据连接缓冲（M5c-2 真端到端）。
///
/// agent 启动时建 N 条 data 连接；agent 通过 `PoolReady{count}` 通知 gateway；
/// gateway 立刻向该 agent 发 N 条 `OpenStream{conn_id=1..=N, stream_id=0}` 占位；
/// agent 在每条预热连接上写 `StreamConn{conn_id}`；gateway 配对后入本池。
/// 用户态真实请求时，从池取一条（O(1)）→ `OpenStream{conn_id=0}` 通知 agent「使用这条」，
/// 节省 OpenStream→拨号→StreamConn 的 ~5 RTT 用户态延迟。
///
/// 池按 (device_id, tunnel_id) 维度隔离；空池时取 None → 回退拨号路径。
/// 池内条目：(conn_id, 预热连接)。
pub type PoolEntry = (u32, TcpStream);
type TunnelQueue = VecDeque<PoolEntry>;

pub struct DataConnPool {
    by_tunnel: Mutex<HashMap<(String, String), TunnelQueue>>,
}

impl Default for DataConnPool {
    fn default() -> Self {
        Self::new()
    }
}

impl DataConnPool {
    pub fn new() -> Self {
        Self {
            by_tunnel: Mutex::new(HashMap::new()),
        }
    }

    /// 用户态请求到达：从池取一条空闲连接（连同其 conn_id，用于激活指令）。
    pub fn take(&self, device_id: &str, tunnel_id: &str) -> Option<(u32, TcpStream)> {
        let mut map = self.by_tunnel.lock().unwrap();
        map.get_mut(&(device_id.to_string(), tunnel_id.to_string()))?
            .pop_front()
    }

    /// agent 数据连接到达（首帧 StreamConn{stream_id=0, conn_id=k} 已读出），登记入池。
    /// `conn_id == 0` 表示 agent 拨号的业务连接（非预热），不入池。
    pub fn put(&self, device_id: &str, tunnel_id: &str, conn_id: u32, conn: TcpStream) {
        if conn_id == 0 {
            drop(conn);
            return;
        }
        let mut map = self.by_tunnel.lock().unwrap();
        map.entry((device_id.to_string(), tunnel_id.to_string()))
            .or_default()
            .push_back((conn_id, conn));
    }

    /// 总空闲数（跨所有 (device, tunnel) 对）。
    pub fn total(&self) -> usize {
        let map = self.by_tunnel.lock().unwrap();
        map.values().map(|q| q.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_empty_returns_none() {
        let p = DataConnPool::new();
        assert!(p.take("dev1", "web").is_none());
        assert_eq!(p.total(), 0);
    }
}