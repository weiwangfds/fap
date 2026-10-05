//! M2+ 协议扩展测试：配置下发、访问器接入、隧道路由字段。

use fap_protocol::{
    encode, FrameDecoder, Message, TunnelConfig, MSG_ACCESS_REQUEST, MSG_CONFIG_ACK,
    MSG_CONFIG_PUSH,
};
use serde_json::json;

fn tunnel(id: &str, port: u16) -> TunnelConfig {
    TunnelConfig {
        tunnel_id: id.into(),
        listen_port: port,
        target_host: "127.0.0.1".into(),
        target_port: 8080,
        ..Default::default()
    }
}

#[test]
fn config_push_roundtrip_and_kind() {
    let msg = Message::ConfigPush {
        revision: 7,
        tunnels: vec![tunnel("web", 7200)],
    };
    assert_eq!(msg.kind(), MSG_CONFIG_PUSH);
    let bytes = encode(&msg).unwrap();
    assert_eq!(bytes[4], MSG_CONFIG_PUSH);
    let mut dec = FrameDecoder::new();
    dec.feed(&bytes);
    assert_eq!(dec.next_message().unwrap().unwrap(), msg);
}

#[test]
fn config_ack_serializes_snake_case() {
    let msg = Message::ConfigAck {
        ok: true,
        error: None,
        revision: 7,
    };
    assert_eq!(msg.kind(), MSG_CONFIG_ACK);
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v,
        json!({"type": "config_ack", "ok": true, "error": null, "revision": 7})
    );
}

#[test]
fn access_request_serializes() {
    let msg = Message::AccessRequest {
        tunnel_id: "ssh".into(),
        token: "tok".into(),
    };
    assert_eq!(msg.kind(), MSG_ACCESS_REQUEST);
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v,
        json!({"type": "access_request", "tunnel_id": "ssh", "token": "tok"})
    );
}

#[test]
fn tunnel_config_supports_shared_port_routes() {
    let t = TunnelConfig {
        tunnel_id: "web".into(),
        listen_port: 0,
        target_host: "127.0.0.1".into(),
        target_port: 8080,
        host: Some("nas.example.com".into()),
        path: None,
        sni: Some("nas.example.com".into()),
        access_token: Some("t0".into()),
        allowed_ips: vec!["192.168.1.0/24".into()],
        max_concurrent: Some(3),
    };
    let v = serde_json::to_value(&t).unwrap();
    assert_eq!(v["host"], json!("nas.example.com"));
    assert_eq!(v["sni"], json!("nas.example.com"));
    assert_eq!(v["access_token"], json!("t0"));
    assert_eq!(v["allowed_ips"], json!(["192.168.1.0/24"]));
    assert_eq!(v["max_concurrent"], json!(3));
    let back: TunnelConfig = serde_json::from_value(v).unwrap();
    assert_eq!(back, t);
}

#[test]
fn tunnel_config_old_json_still_deserializes() {
    // M1 时代的 JSON（无新字段）必须兼容
    let old = json!({
        "tunnel_id": "web",
        "listen_port": 7200,
        "target_host": "127.0.0.1",
        "target_port": 8080
    });
    let t: TunnelConfig = serde_json::from_value(old).unwrap();
    assert_eq!(t.tunnel_id, "web");
    assert_eq!(t.host, None);
    assert_eq!(t.allowed_ips, Vec::<String>::new());
    assert_eq!(t.max_concurrent, None);
}

#[test]
fn register_ack_carries_applied_tunnels() {
    let msg = Message::RegisterAck {
        ok: true,
        error: None,
        data_port: 7101,
        listeners: vec![],
        applied_tunnels: vec![tunnel("web", 7200)],
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v["applied_tunnels"][0]["tunnel_id"], json!("web"));
    let back: Message = serde_json::from_value(v).unwrap();
    assert_eq!(back, msg);
}
