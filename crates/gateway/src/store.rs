//! 设备隧道配置存储：控制台是配置的事实源，落盘 JSON 以便网关重启不丢。

use std::collections::HashMap;
use std::path::PathBuf;

use fap_protocol::TunnelConfig;

pub struct TunnelStore {
    file: Option<PathBuf>,
    configs: HashMap<String, Vec<TunnelConfig>>,
}

impl TunnelStore {
    pub fn new(file: Option<PathBuf>) -> anyhow::Result<Self> {
        let configs = match &file {
            Some(p) if p.exists() => {
                let raw = std::fs::read_to_string(p)?;
                serde_json::from_str(&raw)?
            }
            _ => HashMap::new(),
        };
        Ok(Self { file, configs })
    }

    pub fn get(&self, device_id: &str) -> Option<Vec<TunnelConfig>> {
        self.configs.get(device_id).cloned()
    }

    pub fn set(&mut self, device_id: &str, tunnels: Vec<TunnelConfig>) -> anyhow::Result<()> {
        self.configs.insert(device_id.to_string(), tunnels);
        if let Some(p) = &self.file {
            let raw = serde_json::to_string_pretty(&self.configs)?;
            std::fs::write(p, raw)?;
        }
        Ok(())
    }

    pub fn devices(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }

    /// 控制台覆盖优先，否则用 agent 声明。
    pub fn effective(&self, device_id: &str, declared: Vec<TunnelConfig>) -> Vec<TunnelConfig> {
        self.configs
            .get(device_id)
            .cloned()
            .unwrap_or(declared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, port: u16) -> TunnelConfig {
        TunnelConfig {
            tunnel_id: id.into(),
            listen_port: port,
            target_host: "127.0.0.1".into(),
            target_port: 80,
            ..Default::default()
        }
    }

    fn temp_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fap-store-test-{}-{}.json", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn set_then_get_roundtrip() {
        let file = temp_file("roundtrip");
        let mut s = TunnelStore::new(Some(file.clone())).unwrap();
        s.set("dev1", vec![t("web", 7200)]).unwrap();
        assert_eq!(s.get("dev1"), Some(vec![t("web", 7200)]));
        assert_eq!(s.devices(), vec!["dev1".to_string()]);
        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn persists_across_reopen() {
        let file = temp_file("persist");
        {
            let mut s = TunnelStore::new(Some(file.clone())).unwrap();
            s.set("dev1", vec![t("web", 7200)]).unwrap();
        }
        let s2 = TunnelStore::new(Some(file.clone())).unwrap();
        assert_eq!(s2.get("dev1"), Some(vec![t("web", 7200)]), "重开加载已落盘配置");
        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn missing_file_starts_empty() {
        let file = temp_file("missing");
        let s = TunnelStore::new(Some(file)).unwrap();
        assert_eq!(s.get("dev1"), None);
        assert!(s.devices().is_empty());
    }

    #[test]
    fn effective_prefers_console_override() {
        let mut s = TunnelStore::new(None).unwrap();
        s.set("dev1", vec![t("from-console", 7300)]).unwrap();
        let eff = s.effective("dev1", vec![t("from-agent", 0)]);
        assert_eq!(eff, vec![t("from-console", 7300)]);
    }

    #[test]
    fn effective_falls_back_to_declared() {
        let s = TunnelStore::new(None).unwrap();
        let eff = s.effective("dev1", vec![t("from-agent", 0)]);
        assert_eq!(eff, vec![t("from-agent", 0)]);
    }
}
