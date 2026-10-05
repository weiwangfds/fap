//! fap-demo：一条命令验证完整链路。
//! 进程内拉起 echo 服务（模拟内网服务）、网关、客户端，然后以用户身份
//! 访问网关的隧道端口，验证数据经公网端口中转到达内网服务并返回。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fap_agent::{run_agent, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::TunnelConfig;

async fn spawn_echo() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:9100").await?;
    let addr = listener.local_addr()?;
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
    Ok(addr)
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        println!("== fap 演示 ==");
        let echo = spawn_echo().await?;
        println!("[1] 内网 echo 服务就绪: {echo}");

        let gw = Gateway::start(GatewayConfig {
            control_addr: "127.0.0.1:7100".parse()?,
            data_addr: "127.0.0.1:7101".parse()?,
            auth: HashMap::from([("demo-device".to_string(), "demo-secret".to_string())]),
            ..Default::default()
        })
        .await?;
        println!(
            "[2] 网关就绪: 控制 {} / 数据 {}",
            gw.control_addr, gw.data_addr
        );

        tokio::spawn(run_agent(AgentConfig {
            server_addr: "127.0.0.1:7100".to_string(),
            device_id: "demo-device".into(),
            token: "demo-secret".into(),
            tunnels: vec![TunnelConfig {
                tunnel_id: "web".into(),
                listen_port: 7200,
                target_host: echo.ip().to_string(),
                target_port: echo.port(),
                ..Default::default()
            }],
            heartbeat_interval: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
        }));

        // 等 agent 注册、隧道监听就绪
        let mut tunnel_port = None;
        for _ in 0..100 {
            tunnel_port = gw.tunnel_port("demo-device", "web");
            if tunnel_port.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let port = tunnel_port.expect("隧道未在 5 秒内就绪");
        println!("[3] 客户端已注册，隧道 web -> 内网 {echo}，公网入口 127.0.0.1:{port}");

        let mut user = TcpStream::connect(("127.0.0.1", port)).await?;
        let payload = b"hello from outside!";
        user.write_all(payload).await?;
        let mut got = vec![0u8; payload.len()];
        user.read_exact(&mut got).await?;

        println!(
            "[4] 用户发送 {:?}，经隧道收到 {:?}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(&got)
        );
        assert_eq!(&got, payload, "回显不一致");
        println!("\n[OK] 端到端穿透成功：公网端口 {port} 的流量已到达内网服务并原路返回。");
        gw.shutdown().await;
        Ok(())
    })
}
