//! 流匹配器：把网关侧「等待数据连接」的请求与 agent 回连的数据连接配对。

use std::collections::HashMap;

use tokio::sync::oneshot;

pub struct StreamMatcher<T> {
    waiting: HashMap<u64, oneshot::Sender<T>>,
}

impl<T> Default for StreamMatcher<T> {
    fn default() -> Self {
        Self {
            waiting: HashMap::new(),
        }
    }
}

impl<T> StreamMatcher<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn wait(&mut self, stream_id: u64, tx: oneshot::Sender<T>) {
        self.waiting.insert(stream_id, tx);
    }

    /// 送达等待者则 true；无等待者或等待方已放弃则 false。
    pub fn complete(&mut self, stream_id: u64, value: T) -> bool {
        match self.waiting.remove(&stream_id) {
            Some(tx) => tx.send(value).is_ok(),
            None => false,
        }
    }

    pub fn cancel(&mut self, stream_id: u64) -> bool {
        self.waiting.remove(&stream_id).is_some()
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_then_complete_delivers_value() {
        let mut m = StreamMatcher::new();
        let (tx, rx) = oneshot::channel();
        m.wait(1, tx);
        assert_eq!(m.len(), 1);

        assert!(m.complete(1, 42u32));
        assert_eq!(rx.await.unwrap(), 42);
        assert!(m.is_empty(), "配对成功后应移除等待项");
    }

    #[tokio::test]
    async fn complete_unknown_stream_returns_false() {
        let mut m: StreamMatcher<u32> = StreamMatcher::new();
        assert!(!m.complete(99, 1));
    }

    #[tokio::test]
    async fn complete_after_waiter_gone_returns_false() {
        let mut m = StreamMatcher::new();
        let (tx, rx) = oneshot::channel::<u32>();
        m.wait(1, tx);
        drop(rx); // 等待方（用户连接）已放弃
        assert!(!m.complete(1, 9));
        assert!(m.is_empty(), "失败的配对也应清理等待项");
    }

    #[tokio::test]
    async fn cancel_removes_wait_once() {
        let mut m = StreamMatcher::new();
        let (tx, _rx) = oneshot::channel::<u32>();
        m.wait(1, tx);
        assert!(m.cancel(1));
        assert!(!m.cancel(1));
        assert!(m.is_empty());
    }
}
