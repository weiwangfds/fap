//! M5b 验收：admin 登录签发会话令牌；会话令牌可访问 API；过期/伪造拒绝。

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use fap_gateway::{Gateway, GatewayConfig};

/// 极简 HTTP 客户端（POST/GET，Connection: close）。
async fn http(
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn base_config() -> GatewayConfig {
    GatewayConfig {
        control_addr: "127.0.0.1:0".parse().unwrap(),
        data_addr: "127.0.0.1:0".parse().unwrap(),
        admin_addr: Some("127.0.0.1:0".parse().unwrap()),
        admin_token: Some("master-tk".into()),
        auth: HashMap::new(),
        ..Default::default()
    }
}

#[tokio::test]
async fn login_issues_session_that_grants_access() {
    let gw = Gateway::start(base_config()).await.unwrap();
    let port = gw.admin_addr().unwrap().port();

    // 错误主令牌 → 401
    let (status, _) = http(port, "POST", "/api/auth/login", None, Some(r#"{"token":"bad"}"#)).await;
    assert_eq!(status, 401);

    // 正确主令牌 → 签发会话
    let (status, body) =
        http(port, "POST", "/api/auth/login", None, Some(r#"{"token":"master-tk","ttl_secs":60}"#))
            .await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let session = v["session"].as_str().expect("应含 session 字段").to_string();
    assert!(!session.is_empty());

    // 会话令牌可访问受保护端点
    let (status, _) = http(port, "GET", "/api/devices", Some(&session), None).await;
    assert_eq!(status, 200, "会话令牌应放行");
}

#[tokio::test]
async fn forged_session_token_rejected() {
    let gw = Gateway::start(base_config()).await.unwrap();
    let port = gw.admin_addr().unwrap().port();
    // 伪造：巨大 expiry + 乱签名
    let forged = format!("{:x}.{}", u64::MAX, "0".repeat(64));
    let (status, _) = http(port, "GET", "/api/devices", Some(&forged), None).await;
    assert_eq!(status, 401, "伪造会话必须拒绝");
}

#[tokio::test]
async fn master_token_still_works_directly() {
    let gw = Gateway::start(base_config()).await.unwrap();
    let port = gw.admin_addr().unwrap().port();
    let (status, _) = http(port, "GET", "/api/devices", Some("master-tk"), None).await;
    assert_eq!(status, 200, "主令牌直连仍应放行");
}