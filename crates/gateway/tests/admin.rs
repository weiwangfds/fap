//! M2 验收：admin API —— 控制台读写设备隧道配置并实时下发到 agent。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fap_agent::{run_agent_session, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::TunnelConfig;

async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
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

/// 极简 HTTP/1.1 客户端：发送请求并读完整响应（Connection: close）。
async fn http_request(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp).to_string();
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

async fn wait_tunnel_port(gw: &Gateway, device: &str, tunnel: &str) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(p) = gw.tunnel_port(device, tunnel) {
            return p;
        }
        if Instant::now() > deadline {
            panic!("隧道 {device}/{tunnel} 5 秒内未就绪");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn tunnel_json(id: &str, port: u16, target_port: u16) -> String {
    format!(
        r#"{{"tunnel_id":"{id}","listen_port":{port},"target_host":"127.0.0.1","target_port":{target_port}}}"#
    )
}

#[tokio::test]
async fn admin_api_requires_bearer_token() {
    let gw = Gateway::start(base_config(0)).await.unwrap();
    let port = gw.admin_addr().unwrap().port();
    let (status, _) = http_request(port, "GET", "/api/health", None, None).await;
    assert_eq!(status, 401, "无令牌必须被拒绝");
    let (status, _) = http_request(port, "GET", "/api/health", Some("wrong"), None).await;
    assert_eq!(status, 401, "错误令牌必须被拒绝");
    let (status, body) = http_request(port, "GET", "/api/health", Some("admin-tk"), None).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"ok\""), "健康检查应返回 ok 字段");
}

#[tokio::test]
async fn devices_endpoint_lists_registered_device_and_tunnels() {
    let echo = spawn_echo().await;
    let mut cfg = base_config(0);
    cfg.control_addr = "127.0.0.1:0".parse().unwrap();
    let gw = Gateway::start(cfg).await.unwrap();
    let port = gw.admin_addr().unwrap().port();

    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
            user: String::new(),
            pk: None,
        token: "secret".into(),
        tunnels: vec![TunnelConfig {
            tunnel_id: "web".into(),
            listen_port: 0,
            target_host: echo.ip().to_string(),
            target_port: echo.port(),
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    wait_tunnel_port(&gw, "dev1", "web").await;

    let (status, body) = http_request(port, "GET", "/api/devices", Some("admin-tk"), None).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"device_id\":\"dev1\""), "应列出 dev1: {body}");
    assert!(body.contains("\"online\":true"), "dev1 应在线");
    assert!(body.contains("\"tunnel_id\":\"web\""), "应包含隧道 web");
}

#[tokio::test]
async fn put_tunnels_pushes_config_to_running_agent() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config(0)).await.unwrap();
    let port = gw.admin_addr().unwrap().port();

    // agent 以空隧道注册
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
            user: String::new(),
            pk: None,
        token: "secret".into(),
        tunnels: vec![],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 控制台下发隧道 web -> echo
    let body = format!("[{}]", tunnel_json("web", 0, echo.port()));
    let (status, resp) = http_request(
        port,
        "PUT",
        "/api/devices/dev1/tunnels",
        Some("admin-tk"),
        Some(&body),
    )
    .await;
    assert_eq!(status, 200, "下发应成功: {resp}");

    // 新隧道生效：可从公网端口访问到内网 echo
    let tunnel_port = wait_tunnel_port(&gw, "dev1", "web").await;
    let mut user = TcpStream::connect(("127.0.0.1", tunnel_port)).await.unwrap();
    user.write_all(b"pushed from console").await.unwrap();
    let mut buf = vec![0u8; 19];
    user.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, b"pushed from console");
}

#[tokio::test]
async fn put_tunnels_replaces_old_listeners() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config(0)).await.unwrap();
    let port = gw.admin_addr().unwrap().port();

    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
            user: String::new(),
            pk: None,
        token: "secret".into(),
        tunnels: vec![],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    tokio::time::sleep(Duration::from_millis(300)).await;

    let body = format!("[{}]", tunnel_json("old", 0, echo.port()));
    let (status, _) = http_request(port, "PUT", "/api/devices/dev1/tunnels", Some("admin-tk"), Some(&body)).await;
    assert_eq!(status, 200);
    let old_port = wait_tunnel_port(&gw, "dev1", "old").await;

    // 换成新隧道
    let body = format!("[{}]", tunnel_json("new", 0, echo.port()));
    let (status, _) = http_request(port, "PUT", "/api/devices/dev1/tunnels", Some("admin-tk"), Some(&body)).await;
    assert_eq!(status, 200);
    let new_port = wait_tunnel_port(&gw, "dev1", "new").await;

    assert_eq!(gw.tunnel_port("dev1", "old"), None, "旧隧道应被移除");
    // 新隧道可用
    let mut user = TcpStream::connect(("127.0.0.1", new_port)).await.unwrap();
    let payload = b"after replace";
    user.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    user.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, payload);
    let _ = old_port;
}
