//! Admin API 在 /api/devices 中返回设备元信息（hostname/os/arch/version/user）。

use std::collections::HashMap;
use std::time::Duration;

use fap_agent::{run_agent_session, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::{TunnelConfig, MSG_REGISTER};

async fn http_get(port: u16, path: &str, bearer: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn base_config(admin_port: u16) -> GatewayConfig {
    GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        admin_addr: Some(format!("127.0.0.1:{admin_port}").parse().unwrap()),
        admin_token: Some("admin-tk".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn admin_devices_includes_dm_metadata() {
    let gw = Gateway::start(base_config(0)).await.unwrap();
    let port = gw.admin_addr().unwrap().port();

    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: "alice".into(),
        pk: None,
        tunnels: vec![TunnelConfig {
            tunnel_id: "web".into(),
            listen_port: 0,
            target_host: "127.0.0.1".into(),
            target_port: 8080,
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    for _ in 0..50 {
        if gw.is_online("dev1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gw.is_online("dev1"));

    let (status, body) = http_get(port, "/api/devices", "admin-tk").await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let dev = &v["devices"][0];
    assert_eq!(dev["device_id"], "dev1");
    assert_eq!(dev["online"], true);
    let info = &dev["device_info"];
    assert!(info["hostname"].is_string(), "hostname 应为字符串");
    assert_eq!(info["user"], "alice", "user 字段应透传");
    assert!(info["os"].is_string(), "os 应上报");
    assert!(info["arch"].is_string(), "arch 应上报");
    assert!(info["version"].is_string(), "version 应上报");

    assert_eq!(MSG_REGISTER, 1);
}