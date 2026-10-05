//! 消息序列化格式测试 —— 锁定 wire format，保证前后兼容。

use fap_protocol::{ListenerInfo, Message, TunnelConfig};
use serde_json::json;

#[test]
fn message_json_uses_snake_case_type_tag() {
    let msg = Message::Heartbeat { timestamp_ms: 99 };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v, json!({"type": "heartbeat", "timestamp_ms": 99}));

    let msg = Message::StreamConn { stream_id: 3 };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v, json!({"type": "stream_conn", "stream_id": 3}));

    let msg = Message::OpenStream {
        stream_id: 3,
        tunnel_id: "web".into(),
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v, json!({"type": "open_stream", "stream_id": 3, "tunnel_id": "web"}));
}

#[test]
fn register_serializes_tunnels() {
    let msg = Message::Register {
        device_id: "dev1".into(),
        token: "s".into(),
        device_info: None,
        pk: None,
        tunnels: vec![TunnelConfig {
            tunnel_id: "web".into(),
            listen_port: 7200,
            target_host: "127.0.0.1".into(),
            target_port: 8080,
            ..Default::default()
        }],
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v,
        json!({
            "type": "register",
            "device_id": "dev1",
            "token": "s",
            "device_info": null,
            "pk": null,
            "tunnels": [{
                "tunnel_id": "web",
                "listen_port": 7200,
                "target_host": "127.0.0.1",
                "target_port": 8080,
                "host": null,
                "path": null,
                "sni": null,
                "access_token": null,
                "allowed_ips": [],
                "max_concurrent": null
            }]
        })
    );
}

#[test]
fn register_ack_serializes_listeners() {
    let msg = Message::RegisterAck {
        ok: true,
        error: None,
        data_port: 7101,
        listeners: vec![ListenerInfo {
            tunnel_id: "web".into(),
            listen_port: 7200,
        }],
        applied_tunnels: vec![],
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v,
        json!({
            "type": "register_ack",
            "ok": true,
            "error": null,
            "data_port": 7101,
            "listeners": [{"tunnel_id": "web", "listen_port": 7200}],
            "applied_tunnels": []
        })
    );
}
