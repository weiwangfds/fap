//! M2.5c 验收：HMAC-SHA256 challenge-response 注册。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fap_agent::{run_agent_session, AgentConfig};
use fap_gateway::{Gateway, GatewayConfig};
use fap_protocol::{
    hmac, read_message, write_message, FrameDecoder, Message, HMAC_BYTES, MSG_AUTH_CHALLENGE,
    MSG_AUTH_CHALLENGE_RESP,
};

fn base_config(hmac_secret: Option<[u8; HMAC_BYTES]>) -> GatewayConfig {
    let mut auth = HashMap::new();
    if hmac_secret.is_some() {
        // HMAC 模式下 auth 表留空（HMAC 优先）
        auth.insert("dev1".to_string(), "legacy-unused".to_string());
    } else {
        auth.insert("dev1".to_string(), "secret".to_string());
    }
    let mut auth_hmac = HashMap::new();
    if let Some(secret) = hmac_secret {
        auth_hmac.insert("dev1".to_string(), secret);
    }
    GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        auth,
        auth_hmac,
        ..Default::default()
    }
}

fn wait_tunnel_port(gw: &Gateway, device: &str, tunnel: &str) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(p) = gw.tunnel_port(device, tunnel) {
            return p;
        }
        if Instant::now() > deadline {
            panic!("隧道未就绪");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tokio::test]
async fn hmac_register_handshake_with_valid_signature() {
    let secret = [0x11u8; HMAC_BYTES];
    // 我们手动模拟 agent：发 Register → 等 Challenge → 应答 → 等 RegisterAck
    let gw = Gateway::start(base_config(Some(secret))).await.unwrap();
    let mut conn = TcpStream::connect(("127.0.0.1", gw.control_addr.port()))
        .await
        .unwrap();
    let mut dec = FrameDecoder::new();
    // 1. Register：token 字段填明文占位符，agent 实际不需要有效 token（Hmac 模式验证签名而非 token）
    write_message(
        &mut conn,
        &Message::Register {
            device_id: "dev1".into(),
            token: "ignored".into(),
            device_info: None,
            pk: None,
            tunnels: vec![],
        },
    )
    .await
    .unwrap();
    // 2. 收到 AuthChallenge
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
    let Message::AuthChallenge { nonce, ts_ms } = msg else {
        panic!("期望 AuthChallenge，收到 {msg:?}");
    };
    // 3. 计算签名并应答
    let sig = hmac::compute(&secret, &nonce, ts_ms);
    write_message(
        &mut conn,
        &Message::AuthChallengeResp { sig, ts_ms },
    )
    .await
    .unwrap();
    // 4. 收到 RegisterAck.ok=true
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
    let Message::RegisterAck { ok, error, .. } = msg else {
        panic!("期望 RegisterAck，收到 {msg:?}");
    };
    assert!(ok, "签名正确应被接受: {error:?}");
}

#[tokio::test]
async fn hmac_register_rejects_bad_signature() {
    let secret = [0x22u8; HMAC_BYTES];
    let gw = Gateway::start(base_config(Some(secret))).await.unwrap();
    let mut conn = TcpStream::connect(("127.0.0.1", gw.control_addr.port()))
        .await
        .unwrap();
    let mut dec = FrameDecoder::new();
    write_message(
        &mut conn,
        &Message::Register {
            device_id: "dev1".into(),
            token: "ignored".into(),
            device_info: None,
            pk: None,
            tunnels: vec![],
        },
    )
    .await
    .unwrap();
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
    let Message::AuthChallenge { nonce, ts_ms } = msg else {
        panic!();
    };
    // 错误签名
    let bad = [0u8; HMAC_BYTES];
    write_message(
        &mut conn,
        &Message::AuthChallengeResp {
            sig: bad,
            ts_ms,
        },
    )
    .await
    .unwrap();
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
let Message::RegisterAck { ok, error, .. } = msg else {
        panic!("期望拒绝 RegisterAck，收到 {msg:?}");
    };
    assert!(!ok);
    assert!(error.unwrap_or_default().contains("签名"));
}

#[tokio::test]
async fn legacy_token_still_works() {
    // 不启用 HMAC 表，回归 M2 行为：明文 token 仍可用
    let gw = Gateway::start(base_config(None)).await.unwrap();
    tokio::spawn(run_agent_session(AgentConfig {
        server_addr: format!("127.0.0.1:{}", gw.control_addr.port()),
        device_id: "dev1".into(),
        token: "secret".into(),
        user: String::new(),
        pk: None,
        tunnels: vec![],
        heartbeat_interval: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(3),
    }));
    for _ in 0..50 {
        if gw.is_online("dev1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gw.is_online("dev1"), "明文 token 注册应仍工作");
}

#[tokio::test]
async fn hmac_skewed_timestamp_is_rejected() {
    let secret = [0x33u8; HMAC_BYTES];
    let gw = Gateway::start(base_config(Some(secret))).await.unwrap();
    let mut conn = TcpStream::connect(("127.0.0.1", gw.control_addr.port()))
        .await
        .unwrap();
    let mut dec = FrameDecoder::new();
    write_message(
        &mut conn,
        &Message::Register {
            device_id: "dev1".into(),
            token: "ignored".into(),
            device_info: None,
            pk: None,
            tunnels: vec![],
        },
    )
    .await
    .unwrap();
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
    let Message::AuthChallenge { nonce, ts_ms } = msg else {
        panic!();
    };
    // 故意使用过期 ts
    let skewed = ts_ms.wrapping_sub(Duration::from_secs(120).as_millis() as u64);
    let sig = hmac::compute(&secret, &nonce, skewed);
    write_message(
        &mut conn,
        &Message::AuthChallengeResp {
            sig,
            ts_ms: skewed,
        },
    )
    .await
    .unwrap();
    let msg = read_message(&mut conn, &mut dec).await.unwrap();
    let Message::RegisterAck { ok, error, .. } = msg else {
        panic!();
    };
    assert!(!ok, "过期的 ts 应被拒绝");
    let msg = error.unwrap_or_default();
    assert!(msg.contains("过期") || msg.contains("ts"));
}