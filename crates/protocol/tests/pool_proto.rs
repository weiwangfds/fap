//! M5c 协议扩展：OpenStream + StreamConn 增加 `conn_id` 字段（0 = 旧路径；>0 = 数据连接池索引）。

use fap_protocol::{Message, MSG_OPEN_STREAM, MSG_STREAM_CONN};

#[test]
fn open_stream_carries_conn_id_zero_means_unpooled() {
    let m = Message::OpenStream {
        stream_id: 7,
        tunnel_id: "web".into(),
        conn_id: 0,
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["conn_id"], serde_json::json!(0));
    assert_eq!(v["stream_id"], serde_json::json!(7));
    assert_eq!(v["tunnel_id"], serde_json::json!("web"));
}

#[test]
fn stream_conn_carries_conn_id() {
    let m = Message::StreamConn {
        stream_id: 9,
        conn_id: 3,
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["stream_id"], serde_json::json!(9));
    assert_eq!(v["conn_id"], serde_json::json!(3));
}

#[test]
fn legacy_open_stream_wire_is_back_compatible() {
    // M2.5 之前的 OpenStream 没有 conn_id，应被 serde 默认值 0 接受
    let legacy = serde_json::json!({
        "type": "open_stream",
        "stream_id": 1,
        "tunnel_id": "t"
    });
    let m: Message = serde_json::from_value(legacy).unwrap();
    let Message::OpenStream { conn_id, .. } = m else { panic!() };
    assert_eq!(conn_id, 0, "缺省 conn_id 应默认为 0");
}

#[test]
fn legacy_stream_conn_wire_is_back_compatible() {
    let legacy = serde_json::json!({"type": "stream_conn", "stream_id": 1});
    let m: Message = serde_json::from_value(legacy).unwrap();
    let Message::StreamConn { conn_id, .. } = m else { panic!() };
    assert_eq!(conn_id, 0);
}

#[test]
fn kind_byte_unchanged() {
    // 编号字段不动 → 已有设备/网关升级互通
    let m = Message::OpenStream { stream_id: 1, tunnel_id: "t".into(), conn_id: 5 };
    assert_eq!(m.kind(), MSG_OPEN_STREAM);
    let m = Message::StreamConn { stream_id: 1, conn_id: 5 };
    assert_eq!(m.kind(), MSG_STREAM_CONN);
}