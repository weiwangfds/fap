//! M2.5b e2e 验收：流量计数与活跃流数正确累计。

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
            let Ok((mut c, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match c.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if c.write_all(&buf[..n]).await.is_err() {
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

async fn wait_tunnel_port(gw: &Gateway, device: &str, tunnel: &str) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(p) = gw.tunnel_port(device, tunnel) {
            return p;
        }
        if Instant::now() > deadline {
            panic!("隧道未就绪");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn base_config() -> GatewayConfig {
    GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        ..Default::default()
    }
}

#[tokio::test]
async fn metrics_track_bytes_and_counters() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config()).await.unwrap();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
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
    let port = wait_tunnel_port(&gw, "dev1", "web").await;

    let mut a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    a.write_all(b"hello").await.unwrap();
    let mut buf = vec![0u8; 5];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello");
    drop(a);

    // 给 metrics 一点时间 flush 计数
    tokio::time::sleep(Duration::from_millis(200)).await;

    let m = gw.metrics("dev1", "web").expect("metrics 应存在");
    assert_eq!(m.bytes_tx, 5, "5 字节应经用户→agent 一侧记入 tx");
    assert_eq!(m.bytes_rx, 5, "5 字节应经 agent→用户 一侧记入 rx");
    assert_eq!(m.total_streams, 1);
    assert_eq!(m.active_streams, 0, "连接断开后活跃流应归零");
}

#[tokio::test]
async fn metrics_track_concurrent_streams() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config()).await.unwrap();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
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
    let port = wait_tunnel_port(&gw, "dev1", "web").await;

    let mut a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut b = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    a.write_all(b"aaa").await.unwrap();
    b.write_all(b"bbbb").await.unwrap();
    let mut ra = [0u8; 3];
    let mut rb = [0u8; 4];
    a.read_exact(&mut ra).await.unwrap();
    b.read_exact(&mut rb).await.unwrap();
    assert_eq!(&ra[..], b"aaa");
    assert_eq!(&rb[..], b"bbbb");

    tokio::time::sleep(Duration::from_millis(100)).await;
    let m = gw.metrics("dev1", "web").unwrap();
    assert_eq!(m.total_streams, 2, "两条用户连接都计数");
    assert_eq!(m.bytes_tx, 7);
    assert_eq!(m.bytes_rx, 7);
}

#[tokio::test]
async fn admin_endpoint_returns_metrics() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(GatewayConfig {
        admin_addr: Some("127.0.0.1:0".parse().unwrap()),
        admin_token: Some("tk".into()),
        ..base_config()
    })
    .await
    .unwrap();
    let admin_port = gw.admin_addr().unwrap().port();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
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
    let port = wait_tunnel_port(&gw, "dev1", "web").await;

    let mut u = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    u.write_all(b"xy").await.unwrap();
    let mut buf = [0u8; 2];
    u.read_exact(&mut buf).await.unwrap();
    drop(u);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 拉 admin API
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut s = TcpStream::connect(("127.0.0.1", admin_port)).await.unwrap();
    s.write_all(
        b"GET /api/devices/dev1/tunnels/web/metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tk\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp).to_string();
    assert!(text.contains("\"bytes_tx\":2"), "应暴露 bytes_tx: {text}");
    assert!(text.contains("\"bytes_rx\":2"), "应暴露 bytes_rx");
    assert!(text.contains("\"total_streams\":1"), "应暴露 total_streams");
}