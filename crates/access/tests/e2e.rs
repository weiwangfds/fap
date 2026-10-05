//! M4b 验收：fap-access 本地转发端到端。
//! gateway + agent + fap-access 全链路：本地连接 → 访问器 → 共享端口 → 内网 echo。

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fap_access::{run_local_forward, AccessConfig};
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

#[tokio::test]
async fn local_forward_reaches_inner_service() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        shared_addr: Some("127.0.0.1:0".parse().unwrap()),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        ..Default::default()
    })
    .await
    .unwrap();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
        tunnels: vec![TunnelConfig {
            tunnel_id: "ssh".into(),
            listen_port: 0,
            target_host: echo.ip().to_string(),
            target_port: echo.port(),
            access_token: Some("tok-1".into()),
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    // 等设备上线
    for _ in 0..50 {
        if gw.is_online("dev1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gw.is_online("dev1"));

    // 启动 fap-access 本地转发
    let local_addr = run_local_forward(AccessConfig {
        server_addr: format!("127.0.0.1:{}", gw.shared_addr.unwrap().port()),
        tunnel_id: "ssh".into(),
        token: "tok-1".into(),
        listen_addr: "127.0.0.1:0".into(),
        connect_timeout: Duration::from_secs(5),
    })
    .await
    .unwrap();

    // 用户连本地端口，数据应穿透到内网 echo
    let mut u = TcpStream::connect(local_addr).await.unwrap();
    u.write_all(b"HELLO-VIA-ACCESS").await.unwrap();
    let mut buf = vec![0u8; 16];
    u.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"HELLO-VIA-ACCESS");
}

#[tokio::test]
async fn local_forward_with_bad_token_closes_connections() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        shared_addr: Some("127.0.0.1:0".parse().unwrap()),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        ..Default::default()
    })
    .await
    .unwrap();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
        tunnels: vec![TunnelConfig {
            tunnel_id: "ssh".into(),
            listen_port: 0,
            target_host: echo.ip().to_string(),
            target_port: echo.port(),
            access_token: Some("tok-1".into()),
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

    let local_addr = run_local_forward(AccessConfig {
        server_addr: format!("127.0.0.1:{}", gw.shared_addr.unwrap().port()),
        tunnel_id: "ssh".into(),
        token: "WRONG".into(),
        listen_addr: "127.0.0.1:0".into(),
        connect_timeout: Duration::from_secs(5),
    })
    .await
    .unwrap();

    let mut u = TcpStream::connect(local_addr).await.unwrap();
    u.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(3), u.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "错误令牌下不应收到业务数据"
    );
}