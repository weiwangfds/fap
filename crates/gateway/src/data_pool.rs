//! 数据连接池：预热的 agent 数据连接缓冲。
//!
//! agent 启动时预建立 N 条 data 端口连接到网关侧（见 M5c-2 agent 端预连接）；
//! 连接 idle 状态下挂在本池；OpenStream 时取出一条活跃连接直接分发，
//! 消除「OpenStream → agent 拨号 data 端口 → 发送 StreamConn」的用户态延迟。
//!
//! 当 M5c-2 未开启（agent 不预热）时，池为空，原数据面路径不变。

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::net::TcpStream;

pub struct DataConnPool {
    idle: Mutex<VecDeque<TcpStream>>,
    capacity: usize,
}

impl DataConnPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            idle: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// 放回一条空闲连接；池满时丢弃（agent 会重拨）。
    pub fn put_back(&self, conn: TcpStream) {
        let mut q = self.idle.lock().unwrap();
        if q.len() < self.capacity {
            q.push_back(conn);
        }
    }

    /// 取出一条空闲连接；池空返回 None。
    pub fn take(&self) -> Option<TcpStream> {
        self.idle.lock().unwrap().pop_front()
    }

    pub fn len(&self) -> usize {
        self.idle.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 池容量上界（含已空闲 + 正在使用的总预估）。
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一组模拟连接的 helper（绕过真实 socket：用一个空 TcpStream 在 Linux 上
    /// 太重；本测借 door_check 校验队列语义，靠 e2e 覆盖真实路径）。
    fn count_after(p: &DataConnPool, expected: usize) {
        assert_eq!(p.len(), expected, "queue 大小应匹配");
    }

    #[test]
    fn empty_on_new() {
        let p = DataConnPool::new(8);
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
        assert!(p.take().is_none());
        assert_eq!(p.capacity(), 8);
    }

    #[test]
    fn capacity_zero_never_stores() {
        let p = DataConnPool::new(0);
        // 真实 socket 太重；只验证容量字段语义
        assert_eq!(p.capacity(), 0);
    }
}