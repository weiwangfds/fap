//! M3d：TOML 配置解析（网关 + 客户端）。

use fap_protocol::config::{AgentToml, GatewayToml};

#[test]
fn gateway_minimal_toml_parses() {
    let src = r#"
control_addr = "0.0.0.0:7100"
data_addr = "0.0.0.0:7101"
"#;
    let cfg: GatewayToml = toml::from_str(src).unwrap();
    assert_eq!(cfg.control_addr, "0.0.0.0:7100");
    assert_eq!(cfg.data_addr, "0.0.0.0:7101");
    assert!(cfg.shared_addr.is_none());
    assert!(cfg.admin_addr.is_none());
    assert!(cfg.auth.is_empty());
    assert!(cfg.auth_hmac.is_empty());
}

#[test]
fn gateway_full_toml_parses() {
    let src = r#"
control_addr = "0.0.0.0:7100"
data_addr = "0.0.0.0:7101"
shared_addr = "0.0.0.0:443"
admin_addr = "0.0.0.0:7102"
admin_token = "tk-1"
store_file = "tunnels.json"
console_backend = "127.0.0.1:3000"
console_host = "console.example.com"
heartbeat_timeout_secs = 45
stream_setup_timeout_secs = 10

[auth]
dev1 = "secret"

[auth_hmac]
dev2 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#;
    let cfg: GatewayToml = toml::from_str(src).unwrap();
    assert_eq!(cfg.shared_addr.as_deref(), Some("0.0.0.0:443"));
    assert_eq!(cfg.admin_token.as_deref(), Some("tk-1"));
    assert_eq!(cfg.heartbeat_timeout_secs, 45);
    assert_eq!(cfg.stream_setup_timeout_secs, 10);
    assert_eq!(cfg.auth.get("dev1").map(|s| s.as_str()), Some("secret"));
    assert!(cfg.auth_hmac.contains_key("dev2"));
}

#[test]
fn gateway_hmac_secret_must_be_32_bytes_hex() {
    let src = r#"
control_addr = "0.0.0.0:7100"
data_addr = "0.0.0.0:7101"

[auth_hmac]
dev2 = "not-hex"
"#;
    let cfg: GatewayToml = toml::from_str(src).unwrap();
    assert!(cfg.validate().is_err(), "非法 hex 应被 validate 拒绝");
}

#[test]
fn agent_minimal_toml_parses() {
    let src = r#"
server_addr = "gw.example.com:7100"
device_id = "dev1"
token = "secret"

[[tunnels]]
tunnel_id = "web"
listen_port = 7200
target_host = "127.0.0.1"
target_port = 8080
"#;
    let cfg: AgentToml = toml::from_str(src).unwrap();
    assert_eq!(cfg.server_addr, "gw.example.com:7100");
    assert_eq!(cfg.device_id, "dev1");
    assert_eq!(cfg.tunnels.len(), 1);
    assert_eq!(cfg.tunnels[0].tunnel_id, "web");
    assert_eq!(cfg.tunnels[0].target_port, 8080);
}

#[test]
fn agent_shared_tunnel_toml_parses() {
    let src = r#"
server_addr = "gw:7100"
device_id = "dev1"
token = "s"

[[tunnels]]
tunnel_id = "api"
listen_port = 0
target_host = "127.0.0.1"
target_port = 9000
host = "api.example.com"
path = "/api"

[[tunnels]]
tunnel_id = "ssh"
listen_port = 0
target_host = "127.0.0.1"
target_port = 22
access_token = "tok-1"
"#;
    let cfg: AgentToml = toml::from_str(src).unwrap();
    assert_eq!(cfg.tunnels[0].host.as_deref(), Some("api.example.com"));
    assert_eq!(cfg.tunnels[0].path.as_deref(), Some("/api"));
    assert_eq!(cfg.tunnels[1].access_token.as_deref(), Some("tok-1"));
}

#[test]
fn agent_validate_rejects_missing_fields() {
    let src = r#"
server_addr = "gw:7100"
device_id = ""
token = ""

[[tunnels]]
tunnel_id = ""
listen_port = 0
target_host = "127.0.0.1"
target_port = 80
"#;
    let cfg: AgentToml = toml::from_str(src).unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn gateway_validate_rejects_bad_listen_addrs() {
    let src = r#"
control_addr = "not-an-addr"
data_addr = "0.0.0.0:7101"
"#;
    let cfg: GatewayToml = toml::from_str(src).unwrap();
    assert!(cfg.validate().is_err());
}