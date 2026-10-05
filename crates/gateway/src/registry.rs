//! 设备注册表：设备身份认证、在线状态、心跳超时清理。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use fap_protocol::Message;

/// 已注册设备的会话信息。
pub struct DeviceEntry {
    /// 向该设备控制连接下发消息的通道（OpenStream / HeartbeatAck 等）。
    pub control_tx: mpsc::Sender<Message>,
    pub last_heartbeat: Instant,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegisterError {
    #[error("认证失败：设备或令牌错误")]
    BadToken,
}

pub struct DeviceRegistry {
    /// 设备凭证表：device_id -> token。
    auth: HashMap<String, String>,
    devices: HashMap<String, DeviceEntry>,
}

impl DeviceRegistry {
    pub fn new(auth: HashMap<String, String>) -> Self {
        Self {
            auth,
            devices: HashMap::new(),
        }
    }

    /// 注册设备会话。同一设备重复注册会顶替旧会话，返回值指示是否发生了顶替。
    pub fn register(
        &mut self,
        device_id: &str,
        token: &str,
        control_tx: mpsc::Sender<Message>,
        now: Instant,
    ) -> Result<bool, RegisterError> {
        match self.auth.get(device_id) {
            Some(expected) if expected == token => {}
            _ => return Err(RegisterError::BadToken),
        }
        let replaced = self.devices.remove(device_id).is_some();
        self.devices.insert(
            device_id.to_string(),
            DeviceEntry {
                control_tx,
                last_heartbeat: now,
            },
        );
        Ok(replaced)
    }

    pub fn heartbeat(&mut self, device_id: &str, now: Instant) -> bool {
        match self.devices.get_mut(device_id) {
            Some(entry) => {
                entry.last_heartbeat = now;
                true
            }
            None => false,
        }
    }

    pub fn control_tx(&self, device_id: &str) -> Option<mpsc::Sender<Message>> {
        self.devices.get(device_id).map(|e| e.control_tx.clone())
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }

    /// 该会话是否仍是当前注册者——防止被顶替的旧连接在断开时误清理新会话。
    pub fn owns(&self, device_id: &str, tx: &mpsc::Sender<Message>) -> bool {
        self.devices
            .get(device_id)
            .map(|e| e.control_tx.same_channel(tx))
            .unwrap_or(false)
    }

    pub fn force_remove(&mut self, device_id: &str) -> bool {
        self.devices.remove(device_id).is_some()
    }

    /// 清理心跳超时的设备，返回被移除的 device_id。
    pub fn sweep(&mut self, timeout: Duration, now: Instant) -> Vec<String> {
        let stale: Vec<String> = self
            .devices
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_heartbeat) > timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            self.devices.remove(id);
        }
        stale
    }

    pub fn online_count(&self) -> usize {
        self.devices.len()
    }

    /// 全部在线设备 ID（含会话未清理的）。
    pub fn device_ids(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> mpsc::Sender<Message> {
        mpsc::channel(8).0
    }

    fn auth() -> HashMap<String, String> {
        HashMap::from([("dev1".to_string(), "secret".to_string())])
    }

    #[test]
    fn register_with_valid_token_succeeds() {
        let mut r = DeviceRegistry::new(auth());
        let now = Instant::now();
        let replaced = r.register("dev1", "secret", tx(), now).unwrap();
        assert!(!replaced, "首次注册不应报告顶替");
        assert!(r.is_online("dev1"));
        assert_eq!(r.online_count(), 1);
    }

    #[test]
    fn register_with_bad_token_is_rejected() {
        let mut r = DeviceRegistry::new(auth());
        let err = r
            .register("dev1", "wrong", tx(), Instant::now())
            .unwrap_err();
        assert_eq!(err, RegisterError::BadToken);
        assert!(!r.is_online("dev1"));
    }

    #[test]
    fn register_unknown_device_is_rejected() {
        let mut r = DeviceRegistry::new(auth());
        let err = r
            .register("ghost", "secret", tx(), Instant::now())
            .unwrap_err();
        assert_eq!(err, RegisterError::BadToken);
    }

    #[test]
    fn re_register_replaces_session_and_reports_it() {
        let mut r = DeviceRegistry::new(auth());
        let now = Instant::now();
        r.register("dev1", "secret", tx(), now).unwrap();
        let old_tx = r.control_tx("dev1").unwrap();

        let replaced = r.register("dev1", "secret", tx(), now).unwrap();
        assert!(replaced, "重复注册应顶替旧会话");

        let new_tx = r.control_tx("dev1").unwrap();
        assert!(
            !new_tx.same_channel(&old_tx),
            "注册表应持有新会话的通道"
        );
        assert_eq!(r.online_count(), 1, "顶替不增加在线数");
    }

    #[test]
    fn owns_distinguishes_current_and_stale_session() {
        let mut r = DeviceRegistry::new(auth());
        let now = Instant::now();
        r.register("dev1", "secret", tx(), now).unwrap();
        let stale = r.control_tx("dev1").unwrap();
        assert!(r.owns("dev1", &stale));

        r.register("dev1", "secret", tx(), now).unwrap();
        assert!(
            !r.owns("dev1", &stale),
            "旧会话不再是注册者，其断开时不得清理新会话"
        );
    }

    #[test]
    fn heartbeat_refreshes_timestamp() {
        let mut r = DeviceRegistry::new(auth());
        let t0 = Instant::now();
        r.register("dev1", "secret", tx(), t0).unwrap();
        assert_eq!(r.devices["dev1"].last_heartbeat, t0);

        let t1 = t0 + Duration::from_secs(10);
        assert!(r.heartbeat("dev1", t1));
        assert_eq!(r.devices["dev1"].last_heartbeat, t1);
        assert!(!r.heartbeat("ghost", t1), "未知设备心跳返回 false");
    }

    #[test]
    fn sweep_removes_only_stale_devices() {
        let mut r = DeviceRegistry::new(HashMap::from([
            ("dev1".to_string(), "s".to_string()),
            ("dev2".to_string(), "s".to_string()),
        ]));
        let t0 = Instant::now();
        r.register("dev1", "s", tx(), t0).unwrap();
        r.register("dev2", "s", tx(), t0).unwrap();
        // dev1 在 80s 时心跳过，dev2 停留在 0s；判定时刻 100s、超时 30s
        assert!(r.heartbeat("dev1", t0 + Duration::from_secs(80)));

        let now = t0 + Duration::from_secs(100);
        let swept = r.sweep(Duration::from_secs(30), now);
        assert_eq!(swept, vec!["dev2".to_string()]);
        assert!(r.is_online("dev1"));
        assert!(!r.is_online("dev2"));
    }

    #[test]
    fn force_remove_drops_device() {
        let mut r = DeviceRegistry::new(auth());
        r.register("dev1", "secret", tx(), Instant::now()).unwrap();
        assert!(r.force_remove("dev1"));
        assert!(!r.force_remove("dev1"));
        assert!(!r.is_online("dev1"));
    }
}
