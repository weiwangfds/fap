//! 节流器：未授权/失败请求的速率限制（RustDesk 借鉴）。
//! 配对：失败的认证/注册请求被节流 N 秒；同一来源连续失败 5 次则封禁 10 分钟。
//! 跟踪按字符串键（device_id 或 IP）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Throttle(Duration),
    Ban(Duration),
}

#[derive(Debug, Clone)]
struct Entry {
    last_attempt: Instant,
    /// 距 last_attempt 不到 throttle 间隔则拒绝；否则放行并重置窗口。
    throttle: Duration,
    /// 累计连续失败次数（达到阈值升级为 Ban）。
    streak: u32,
    /// 当前封禁到期时间（瞬时；过期则降级回 Allow）。
    banned_until: Option<Instant>,
}

pub struct Throttle {
    throttle: Duration,
    ban_after: u32,
    ban_for: Duration,
    entries: HashMap<String, Entry>,
}

impl Default for Throttle {
    fn default() -> Self {
        Self::with_params(Duration::from_secs(30), 5, Duration::from_secs(10 * 60))
    }
}

impl Throttle {
    pub fn with_params(throttle: Duration, ban_after: u32, ban_for: Duration) -> Self {
        Self {
            throttle,
            ban_after,
            ban_for,
            entries: HashMap::new(),
        }
    }

    /// 决策：成功 → 清除该键的失败计数；失败 → 累计并决策节流/封禁。
    /// 第一次调用（无 entry）默认 Allow 并建立 entry。
    pub fn decide(&mut self, key: &str, now: Instant) -> Decision {
        let needs_create = !self.entries.contains_key(key);
        if needs_create {
            self.entries.insert(
                key.to_string(),
                Entry {
                    last_attempt: now,
                    throttle: self.throttle,
                    streak: 0,
                    banned_until: None,
                },
            );
            return Decision::Allow;
        }
        let e = self.entries.get(key).unwrap();
        if let Some(until) = e.banned_until {
            if until > now {
                return Decision::Ban(until - now);
            }
        }
        if now.duration_since(e.last_attempt) < e.throttle {
            return Decision::Throttle(e.throttle);
        }
        Decision::Allow
    }

    pub fn record_success(&mut self, key: &str, now: Instant) {
        self.entries.remove(key);
        let _ = now;
    }

    pub fn record_failure(&mut self, key: &str, now: Instant) {
        let e = self.entries.entry(key.to_string()).or_insert(Entry {
            last_attempt: now,
            throttle: self.throttle,
            streak: 0,
            banned_until: None,
        });
        e.last_attempt = now;
        e.streak = e.streak.saturating_add(1);
        if e.streak >= self.ban_after {
            e.banned_until = Some(now + self.ban_for);
            e.streak = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_allowed() {
        let mut t = Throttle::default();
        let now = Instant::now();
        assert!(matches!(t.decide("dev1", now), Decision::Allow));
    }

    #[test]
    fn second_call_within_throttle_rejected() {
        let mut t = Throttle::default();
        let now = Instant::now();
        assert!(matches!(t.decide("dev1", now), Decision::Allow));
        match t.decide("dev1", now) {
            Decision::Throttle(_) => {}
            other => panic!("期望 Throttle，实际 {other:?}"),
        }
    }

    #[test]
    fn after_throttle_window_allowed_again() {
        let mut t = Throttle::with_params(Duration::from_millis(50), 100, Duration::from_secs(1));
        let now = Instant::now();
        assert!(matches!(t.decide("k", now), Decision::Allow));
        // 50ms 后放行
        match t.decide("k", now + Duration::from_millis(60)) {
            Decision::Allow => {}
            other => panic!("应放行，实际 {other:?}"),
        }
    }

    #[test]
    fn success_resets_window() {
        let mut t = Throttle::with_params(Duration::from_secs(30), 5, Duration::from_secs(60));
        let now = Instant::now();
        t.record_failure("k", now);
        t.record_failure("k", now + Duration::from_secs(1));
        assert!(matches!(t.decide("k", now + Duration::from_secs(2)), Decision::Throttle(_)));
        t.record_success("k", now + Duration::from_secs(3));
        assert!(matches!(t.decide("k", now + Duration::from_secs(4)), Decision::Allow));
    }

    #[test]
    fn streak_reaching_ban_after_bans_key() {
        let mut t = Throttle::with_params(Duration::from_secs(30), 3, Duration::from_secs(60));
        let now = Instant::now();
        t.record_failure("k", now);
        t.record_failure("k", now + Duration::from_secs(31));
        t.record_failure("k", now + Duration::from_secs(62));
        // 第 3 次失败后被封禁
        match t.decide("k", now + Duration::from_secs(63)) {
            Decision::Ban(_) => {}
            other => panic!("应封禁，实际 {other:?}"),
        }
    }

    #[test]
    fn different_keys_are_independent() {
        let mut t = Throttle::default();
        let now = Instant::now();
        t.record_failure("a", now);
        assert!(matches!(t.decide("a", now), Decision::Throttle(_)));
        assert!(matches!(t.decide("b", now), Decision::Allow));
    }
}