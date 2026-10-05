//! TOML 配置结构（网关 / 客户端共用），参考 rathole 与 sozu 的配置风格。

use serde::{Deserialize, Serialize};

use crate::TunnelConfig;

/// 网关配置（fap-gateway.toml）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GatewayToml {
    #[serde(default = "default_control_addr")]
    pub control_addr: String,
    #[serde(default = "default_data_addr")]
    pub data_addr: String,
    /// 共享单端口（M3）。缺省不启用。
    #[serde(default)]
    pub shared_addr: Option<String>,
    #[serde(default)]
    pub admin_addr: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub store_file: Option<String>,
    #[serde(default)]
    pub console_backend: Option<String>,
    #[serde(default)]
    pub console_host: Option<String>,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_stream_setup_timeout")]
    pub stream_setup_timeout_secs: u64,
    /// 明文 token 表：device_id -> token。
    #[serde(default)]
    pub auth: std::collections::HashMap<String, String>,
    /// HMAC 密钥表：device_id -> 64 位 hex（32 字节）。
    #[serde(default)]
    pub auth_hmac: std::collections::HashMap<String, String>,
}

fn default_control_addr() -> String {
    "0.0.0.0:7100".into()
}
fn default_data_addr() -> String {
    "0.0.0.0:7101".into()
}
fn default_heartbeat_timeout() -> u64 {
    30
}
fn default_stream_setup_timeout() -> u64 {
    8
}

impl GatewayToml {
    pub fn from_toml_str(src: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(src)
    }

    /// 校验地址与 HMAC 密钥格式。
    pub fn validate(&self) -> Result<(), String> {
        use std::net::SocketAddr;
        self.control_addr
            .parse::<SocketAddr>()
            .map_err(|e| format!("control_addr 无效: {e}"))?;
        self.data_addr
            .parse::<SocketAddr>()
            .map_err(|e| format!("data_addr 无效: {e}"))?;
        if let Some(a) = &self.shared_addr {
            a.parse::<SocketAddr>()
                .map_err(|e| format!("shared_addr 无效: {e}"))?;
        }
        if let Some(a) = &self.admin_addr {
            a.parse::<SocketAddr>()
                .map_err(|e| format!("admin_addr 无效: {e}"))?;
        }
        if let Some(a) = &self.console_backend {
            a.parse::<SocketAddr>()
                .map_err(|e| format!("console_backend 无效: {e}"))?;
        }
        for (dev, hex) in &self.auth_hmac {
            decode_hmac_hex(hex).map_err(|e| format!("auth_hmac[{dev}] 无效: {e}"))?;
        }
        Ok(())
    }
}

/// 64 位 hex -> 32 字节。
pub fn decode_hmac_hex(hex: &str) -> Result<[u8; crate::HMAC_BYTES], String> {
    if hex.len() != crate::HMAC_BYTES * 2 {
        return Err(format!("期望 {} 位 hex，实际 {} 位", crate::HMAC_BYTES * 2, hex.len()));
    }
    let mut out = [0u8; crate::HMAC_BYTES];
    for i in 0..crate::HMAC_BYTES {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("第 {i} 字节解析失败: {e}"))?;
    }
    Ok(out)
}

/// 客户端配置（fap-agent.toml）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentToml {
    pub server_addr: String,
    pub device_id: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub user: String,
    /// Ed25519 公钥 hex（64 位）——M2.5d 占位。
    #[serde(default)]
    pub pk: Option<String>,
    #[serde(default = "default_agent_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
}

fn default_agent_heartbeat() -> u64 {
    10
}

impl AgentToml {
    pub fn from_toml_str(src: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(src)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.server_addr.is_empty() {
            return Err("server_addr 不能为空".into());
        }
        if self.device_id.is_empty() {
            return Err("device_id 不能为空".into());
        }
        for t in &self.tunnels {
            if t.tunnel_id.is_empty() {
                return Err("tunnel_id 不能为空".into());
            }
            if t.target_host.is_empty() || t.target_port == 0 {
                return Err(format!("隧道 {} 的内网目标无效", t.tunnel_id));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hmac_hex_roundtrip() {
        let hex = "00ff10".to_string() + &"ab".repeat(29);
        let bytes = decode_hmac_hex(&hex).unwrap();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[31], 0xab);
    }

    #[test]
    fn decode_hmac_hex_rejects_bad_length() {
        assert!(decode_hmac_hex("00").is_err());
    }
}