//! M1 验收测试：端到端穿透 —— 用户 → 网关 → agent → 内网服务。
//! 在同一进程内拉起 echo 服务（模拟内网）、gateway、agent，验证真实 TCP 流量往返。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fap_agent::{run_agent_session, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::TunnelConfig;

/// 内网回显服务：收到什么回什么，直到对端关闭。
async fn spawn_echo() -> SocketAddr {
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

async fn start_gateway() -> Gateway {
    Gateway::start(GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        heartbeat_timeout: Duration::from_secs(30),
        stream_setup_timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .await
    .unwrap()
}

fn agent_config(gw: &Gateway, echo: SocketAddr) -> AgentConfig {
    AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        tunnels: vec![TunnelConfig {
            tunnel_id: "web".into(),
            listen_port: 0, // 自动分配
            target_host: echo.ip().to_string(),
            target_port: echo.port(),
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_millis(200),
        connect_timeout: Duration::from_secs(3),
    }
}

/// 轮询等待隧道端口就绪（agent 注册是异步完成的）。
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

#[tokio::test]
async fn end_to_end_tcp_tunnel_forwards_both_directions() {
    let echo = spawn_echo().await;
    let gw = start_gateway().await;
    tokio::spawn(run_agent_session(agent_config(&gw, echo)));

    let port = wait_tunnel_port(&gw, "dev1", "web").await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    // 用户 → 内网方向
    client.write_all(b"hello fap").await.unwrap();
    let mut buf = vec![0u8; 9];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello fap", "回显应与发送一致（往返双向）");

    // 同一连接上继续收发，验证隧道是持续的而非一次性的
    client.write_all(b"second round").await.unwrap();
    let mut buf2 = vec![0u8; 12];
    client.read_exact(&mut buf2).await.unwrap();
    assert_eq!(buf2, b"second round");
}

#[tokio::test]
async fn concurrent_user_connections_do_not_cross_talk() {
    let echo = spawn_echo().await;
    let gw = start_gateway().await;
    tokio::spawn(run_agent_session(agent_config(&gw, echo)));

    let port = wait_tunnel_port(&gw, "dev1", "web").await;
    let mut a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut b = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    a.write_all(b"AAAA-message").await.unwrap();
    b.write_all(b"BBBB-message").await.unwrap();

    let mut ra = vec![0u8; 12];
    let mut rb = vec![0u8; 12];
    a.read_exact(&mut ra).await.unwrap();
    b.read_exact(&mut rb).await.unwrap();
    assert_eq!(ra, b"AAAA-message");
    assert_eq!(rb, b"BBBB-message");
}

#[tokio::test]
async fn large_payload_roundtrips_intact() {
    let echo = spawn_echo().await;
    let gw = start_gateway().await;
    tokio::spawn(run_agent_session(agent_config(&gw, echo)));

    let port = wait_tunnel_port(&gw, "dev1", "web").await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    client.write_all(&payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "1MB 载荷应分块完整往返");
}

#[tokio::test]
async fn bad_token_agent_is_rejected_and_gateway_stays_healthy() {
    let echo = spawn_echo().await;
    let gw = start_gateway().await;

    let mut bad = agent_config(&gw, echo);
    bad.token = "wrong".into();
    let result = run_agent_session(bad).await;
    assert!(result.is_err(), "错误令牌的注册必须被拒绝");

    // 网关不受影响，且没有留下隧道状态
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(gw.tunnel_port("dev1", "web"), None);

    // 正确令牌的 agent 仍可注册并正常工作
    let cfg = agent_config(&gw, echo);
    tokio::spawn(run_agent_session(cfg));
    let port = wait_tunnel_port(&gw, "dev1", "web").await;
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(b"still alive").await.unwrap();
    let mut buf = vec![0u8; 11];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, b"still alive");
}
