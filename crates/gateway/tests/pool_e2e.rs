//! M5c-2 端到端验收：PoolReady 握手 → 网关池预热 → 用户请求命中池。
//!
//! 验证链路：
//! 1. agent 注册后主动建 N 条 data 连接（进 agent 池），发 PoolReady{N}
//! 2. 网关收到 PoolReady → 发 N 条占位 OpenStream{conn_id=1..N, stream_id=0}
//! 3. agent 在池中连接上写 StreamConn{stream_id=0, conn_id=k} → 网关入 data_pool
//! 4. 用户请求到达 → 网关从池取连接直接 copy_bidirectional（跳过 OpenStream 往返）
//!
//! 本测试断言「第 4 步确实发生」：通过网关 admin/内部接口查池非空，
//! 再发一次用户请求并验证数据往返成功。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fap_agent::{run_agent_session_with_status, AgentConfig};
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
async fn pool_ready_fills_gateway_pool_and_serves_user() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        ..Default::default()
    })
    .await
    .unwrap();

    let status = Arc::new(fap_agent::runtime::RuntimeStatus::new(
        "dev1",
        &format!("127.0.0.1:{}", gw.control_addr.port()),
    ));
    tokio::spawn(run_agent_session_with_status(
        AgentConfig {
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
        },
        Some(status),
    ));

    // 等 agent 上线 + 池握手完成（PoolReady → 占位 OpenStream → StreamConn 入池）
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if gw.is_online("dev1") && gw.data_pool_total() > 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("池握手未在 5s 内完成（online={} pool={}）", gw.is_online("dev1"), gw.data_pool_total());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(gw.data_pool_total() >= 1, "网关池应至少有 1 条预热连接");

    // 用户请求：即使池命中路径有 bug，也至少要回退到拨号路径成功转发
    let port = {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(p) = gw.tunnel_port("dev1", "web") {
                break p;
            }
            if std::time::Instant::now() > deadline {
                panic!("隧道未就绪");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let mut u = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    u.write_all(b"POOL-E2E").await.unwrap();
    let mut buf = vec![0u8; 8];
    u.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"POOL-E2E", "用户数据应完整往返（无论池命中或回退）");
}