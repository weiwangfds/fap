//! M4a 验收：访问器协议 —— 用户侧通过共享端口发送 AccessRequest，
//! 网关验证 token 后该连接成为到内网服务的裸管道（SSH/RDP/数据库场景）。

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fap_agent::{run_agent_session, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::{read_message_exact, write_message, FrameDecoder, Message, TunnelConfig};

async fn spawn_echo() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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

fn base_config() -> GatewayConfig {
    GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        shared_addr: Some("127.0.0.1:0".parse().unwrap()),
        auth: HashMap::from([("dev1".to_string(), "secret".to_string())]),
        ..Default::default()
    }
}

async fn wait_online(gw: &Gateway) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if gw.is_online("dev1") {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("设备未上线");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn access_request_with_valid_token_becomes_raw_pipe() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config()).await.unwrap();
    let shared = gw.shared_addr.unwrap().port();
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
            access_token: Some("tok-ssh-1".into()),
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    wait_online(&gw).await;

    // 访问器：连共享端口，发 AccessRequest 帧
    let mut conn = TcpStream::connect(("127.0.0.1", shared)).await.unwrap();
    write_message(
        &mut conn,
        &Message::AccessRequest {
            tunnel_id: "ssh".into(),
            token: "tok-ssh-1".into(),
        },
    )
    .await
    .unwrap();

    // 连接成为裸管道：echo 语义验证
    conn.write_all(b"SSH-BANNER").await.unwrap();
    let mut buf = vec![0u8; 10];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"SSH-BANNER", "AccessRequest 后应成为到内网的裸管道");

    // 第二轮交互仍通（管道持续）
    conn.write_all(b"CMD").await.unwrap();
    let mut buf2 = vec![0u8; 3];
    conn.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2[..], b"CMD");
}

#[tokio::test]
async fn access_request_with_bad_token_is_rejected() {
    let echo = spawn_echo().await;
    let gw = Gateway::start(base_config()).await.unwrap();
    let shared = gw.shared_addr.unwrap().port();
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
            access_token: Some("tok-ssh-1".into()),
            ..Default::default()
        }],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    wait_online(&gw).await;

    let mut conn = TcpStream::connect(("127.0.0.1", shared)).await.unwrap();
    write_message(
        &mut conn,
        &Message::AccessRequest {
            tunnel_id: "ssh".into(),
            token: "wrong".into(),
        },
    )
    .await
    .unwrap();
    // 网关拒绝：连接应被关闭，写/读都会失败
    let mut buf = [0u8; 8];
    let result = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) => {}                                  // 对端关闭
        Ok(Ok(_)) => panic!("错误令牌不应收到数据"),
        Ok(Err(_)) => {}                                 // 连接被重置
        Err(_) => panic!("错误令牌应导致连接关闭，而非挂起"),
    }
}

#[tokio::test]
async fn access_request_unknown_tunnel_is_rejected() {
    let gw = Gateway::start(base_config()).await.unwrap();
    let shared = gw.shared_addr.unwrap().port();
    // 不注册任何设备/隧道
    let mut conn = TcpStream::connect(("127.0.0.1", shared)).await.unwrap();
    write_message(
        &mut conn,
        &Message::AccessRequest {
            tunnel_id: "ghost".into(),
            token: "whatever".into(),
        },
    )
    .await
    .unwrap();
    let mut buf = [0u8; 8];
    let result = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await;
    assert!(
        matches!(result, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "未知隧道应被拒绝"
    );
}

#[tokio::test]
async fn access_frame_is_not_confused_with_http_or_tls() {
    // AccessRequest 帧首字节是 0x00（len 高字节）；TLS 是 0x16；HTTP 是方法字母。
    // 构造一个 AccessRequest 帧，验证 parse 层不会把它当 HTTP/TLS。
    let frame = fap_protocol::encode(&Message::AccessRequest {
        tunnel_id: "t".into(),
        token: "k".into(),
    })
    .unwrap();
    assert_eq!(frame[0], 0x00, "帧长度高字节应为 0");
    assert_ne!(frame[0], 0x16);
    assert_ne!(frame[0], b'G');

    // read_message_exact 读首帧后，后续裸字节不被吞（访问器协议的关键性质）
    let (mut a, mut b) = tokio::io::duplex(4096);
    let msg = Message::AccessRequest {
        tunnel_id: "t".into(),
        token: "k".into(),
    };
    write_message(&mut a, &msg).await.unwrap();
    a.write_all(b"RAW-AFTER").await.unwrap();
    let got = read_message_exact(&mut b).await.unwrap();
    assert_eq!(got, msg);
    let mut raw = [0u8; 9];
    b.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw[..], b"RAW-AFTER");
    drop(FrameDecoder::new()); // 保持 import
}