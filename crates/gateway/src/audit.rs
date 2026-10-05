//! 审计日志：内存环形缓冲 + JSON Lines 落盘（可选）。
//! 记录：注册成功/失败、配置下发、访问器拒绝、隧道绑定失败。

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AuditEvent {
    /// Unix 毫秒时间戳。
    pub ts_ms: u64,
    /// 事件类别：register_ok / register_fail / config_push / access_reject / bind_fail / throttle。
    pub kind: String,
    /// 主体（device_id / tunnel_id / ip）。
    pub subject: String,
    /// 详情（one line）。
    pub detail: String,
}

pub struct AuditLog {
    ring: Mutex<VecDeque<AuditEvent>>,
    capacity: usize,
    file: Option<PathBuf>,
}

impl AuditLog {
    pub fn new(capacity: usize, file: Option<PathBuf>) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity: capacity.max(1),
            file,
        }
    }

    pub fn record(&self, kind: &str, subject: &str, detail: &str) {
        let ev = AuditEvent {
            ts_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            kind: kind.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
        };
        {
            let mut ring = self.ring.lock().unwrap();
            if ring.len() >= self.capacity {
                ring.pop_front();
            }
            ring.push_back(ev.clone());
        }
        if let Some(f) = &self.file {
            if let Ok(mut w) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
                use std::io::Write;
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = writeln!(w, "{line}");
                }
            }
        }
    }

    /// 返回最近 `limit` 条（新→旧）。
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let ring = self.ring.lock().unwrap();
        ring.iter().rev().take(limit).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.ring.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reads_recent_newest_first() {
        let a = AuditLog::new(10, None);
        a.record("register_ok", "dev1", "first");
        a.record("register_ok", "dev2", "second");
        a.record("register_fail", "dev3", "third");
        let recent = a.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].subject, "dev3", "最新在前");
        assert_eq!(recent[1].subject, "dev2");
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn ring_capacity_drops_oldest() {
        let a = AuditLog::new(2, None);
        a.record("k", "a", "1");
        a.record("k", "b", "2");
        a.record("k", "c", "3");
        assert_eq!(a.len(), 2);
        let recent = a.recent(10);
        assert_eq!(recent[0].subject, "c");
        assert_eq!(recent[1].subject, "b", "最老的 a 被丢弃");
    }

    #[test]
    fn file_persist_appends_jsonl() {
        let mut p = std::env::temp_dir();
        p.push(format!("fap-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let a = AuditLog::new(10, Some(p.clone()));
        a.record("register_ok", "dev1", "hello");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("\"kind\":\"register_ok\""));
        assert!(content.contains("hello"));
        std::fs::remove_file(&p).ok();
    }
}