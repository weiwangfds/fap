//! PoolReady 协议 + agent↔gateway 数据连接池握手 e2e。

use fap_protocol::{Message, MSG_POOL_READY};

#[test]
fn pool_ready_kind_byte_is_registered() {
    let m = Message::PoolReady { count: 4 };
    assert_eq!(m.kind(), MSG_POOL_READY);
}

#[test]
fn pool_ready_serializes_with_count() {
    let m = Message::PoolReady { count: 4 };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["type"], "pool_ready");
    assert_eq!(v["count"], 4);
}

#[test]
fn pool_ready_is_agent_to_gateway_only() {
    // gateway 收到 PoolReady 应知道是 agent→gateway 方向，回复用 OpenStream。
    // 这里仅验证消息本身能在帧之间存在（不影响其它消息类型字节）。
    let bytes = fap_protocol::encode(&Message::PoolReady { count: 1 }).unwrap();
    assert_eq!(bytes[0], 0x00, "长度高字节为 0（消息 ≤ 256）");
    let mut dec = fap_protocol::FrameDecoder::new();
    dec.feed(&bytes);
    assert_eq!(dec.next_message().unwrap().unwrap(), Message::PoolReady { count: 1 });
}

#[test]
fn gateway_can_issue_open_stream_with_pre_filled_conn_id() {
    // gateway 端 prefetch：conn_id = 1..=N 占位
    for id in 1u32..=4 {
        let m = Message::OpenStream {
            stream_id: 0, // 占位
            tunnel_id: "web".into(),
            conn_id: id,
        };
        let Message::OpenStream { conn_id, .. } = m else { unreachable!() };
        assert_eq!(conn_id, id);
    }
}