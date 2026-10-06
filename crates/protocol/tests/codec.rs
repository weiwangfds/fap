//! 帧编解码测试 —— TDD 先行，定义 codec 的行为契约。
//!
//! 帧格式: `[长度 u32 BE][类型 u8][JSON 载荷]`，长度字段 = 类型字节 + 载荷。

use fap_protocol::{
    encode, read_message, read_message_exact, write_message, FrameDecoder, ListenerInfo,
    Message, ProtocolError, TunnelConfig, MAX_FRAME_LEN,
};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sample_messages() -> Vec<Message> {
    let full_tunnel = TunnelConfig {
        tunnel_id: "web".into(),
        listen_port: 0,
        target_host: "127.0.0.1".into(),
        target_port: 8080,
        host: Some("nas.example.com".into()),
        path: Some("/web".into()),
        sni: Some("nas.example.com".into()),
        access_token: Some("t0".into()),
        allowed_ips: vec!["10.0.0.0/8".into()],
        max_concurrent: Some(2),
    };
    vec![
        Message::Register {
            device_id: "dev1".into(),
            token: "secret".into(),
            device_info: None,
            pk: None,
            tunnels: vec![full_tunnel.clone()],
        },
        Message::Register {
            device_id: "dev1".into(),
            token: "secret".into(),
            device_info: None,
            pk: None,
            tunnels: vec![],
        },
        Message::RegisterAck {
            ok: true,
            error: None,
            data_port: 7101,
            listeners: vec![ListenerInfo {
                tunnel_id: "web".into(),
                listen_port: 7200,
            }],
            applied_tunnels: vec![full_tunnel],
        },
        Message::RegisterAck {
            ok: false,
            error: Some("认证失败".into()),
            data_port: 0,
            listeners: vec![],
            applied_tunnels: vec![],
        },
        Message::Heartbeat { timestamp_ms: 123 },
        Message::HeartbeatAck { timestamp_ms: 123 },
        Message::OpenStream {
            stream_id: 42,
            tunnel_id: "web".into(),
            conn_id: 0,
        },
        Message::StreamConn { stream_id: 42, conn_id: 0 },
        Message::ConfigPush {
            revision: 3,
            tunnels: vec![],
        },
        Message::ConfigAck {
            ok: false,
            error: Some("x".into()),
            revision: 3,
        },
        Message::AccessRequest {
            tunnel_id: "ssh".into(),
            token: "tk".into(),
        },
    ]
}

#[test]
fn encode_decode_roundtrip_all_variants() {
    for msg in sample_messages() {
        let bytes = encode(&msg).expect("编码成功");
        let mut dec = FrameDecoder::new();
        dec.feed(&bytes);
        let got = dec.next_message().expect("无解码错误").expect("得到消息");
        assert_eq!(got, msg);
    }
}

#[test]
fn decoder_buffers_partial_input() {
    let msg = Message::Heartbeat { timestamp_ms: 7 };
    let bytes = encode(&msg).unwrap();
    let mut dec = FrameDecoder::new();
    // 逐字节喂入：除最后一字节外都必须返回 None
    for b in &bytes[..bytes.len() - 1] {
        dec.feed(std::slice::from_ref(b));
        assert!(
            dec.next_message().unwrap().is_none(),
            "不完整输入不应产出消息"
        );
    }
    dec.feed(std::slice::from_ref(&bytes[bytes.len() - 1]));
    assert_eq!(dec.next_message().unwrap().unwrap(), msg);
}

#[test]
fn decoder_handles_back_to_back_frames() {
    let a = encode(&Message::Heartbeat { timestamp_ms: 1 }).unwrap();
    let b = encode(&Message::StreamConn { stream_id: 9 }).unwrap();
    let mut all = a.clone();
    all.extend_from_slice(&b);
    let mut dec = FrameDecoder::new();
    dec.feed(&all);
    assert!(dec.next_message().unwrap().is_some());
    assert!(dec.next_message().unwrap().is_some());
    assert!(dec.next_message().unwrap().is_none(), "缓冲耗尽后返回 None");
}

#[test]
fn rejects_oversize_frame_length() {
    let bad_len = (MAX_FRAME_LEN + 1) as u32;
    let header = bad_len.to_be_bytes();
    let mut dec = FrameDecoder::new();
    dec.feed(&header);
    match dec.next_message() {
        Err(ProtocolError::FrameTooLarge(l, max)) => {
            assert_eq!(l, MAX_FRAME_LEN + 1);
            assert_eq!(max, MAX_FRAME_LEN);
        }
        other => panic!("期望 FrameTooLarge，实际 {other:?}"),
    }
}

#[test]
fn rejects_empty_frame() {
    let mut dec = FrameDecoder::new();
    dec.feed(&0u32.to_be_bytes());
    assert!(matches!(
        dec.next_message(),
        Err(ProtocolError::EmptyFrame)
    ));
}

#[test]
fn rejects_unknown_message_type() {
    // 类型字节 99 未定义
    let payload = b"{}";
    let len = (1 + payload.len()) as u32;
    let mut frame = len.to_be_bytes().to_vec();
    frame.push(99);
    frame.extend_from_slice(payload);
    let mut dec = FrameDecoder::new();
    dec.feed(&frame);
    match dec.next_message() {
        Err(ProtocolError::UnknownMessageType(t)) => assert_eq!(t, 99),
        other => panic!("期望 UnknownMessageType，实际 {other:?}"),
    }
}

#[test]
fn rejects_corrupt_payload() {
    let payload = b"xx"; // 非法 JSON
    let len = (1 + payload.len()) as u32;
    let mut frame = len.to_be_bytes().to_vec();
    frame.push(1); // MSG_REGISTER
    frame.extend_from_slice(payload);
    let mut dec = FrameDecoder::new();
    dec.feed(&frame);
    assert!(matches!(
        dec.next_message(),
        Err(ProtocolError::BadPayload(_))
    ));
}

#[test]
fn frame_type_byte_matches_message_kind() {
    for msg in sample_messages() {
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes[4], msg.kind(), "帧中类型字节应等于 kind()");
        let name = Message::kind_name(msg.kind()).expect("kind 可反查名称");
        assert!(!name.is_empty());
    }
}

#[test]
fn unknown_kind_name_is_none() {
    assert!(Message::kind_name(0).is_none());
    assert!(Message::kind_name(200).is_none());
}

#[tokio::test]
async fn async_write_read_roundtrip_over_duplex() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    let msg = Message::OpenStream {
        stream_id: 5,
        tunnel_id: "web".into(),
    };
    write_message(&mut a, &msg).await.expect("写入成功");

    // 控制连接式读取（带解码器）
    let mut dec = FrameDecoder::new();
    let got = read_message(&mut b, &mut dec).await.expect("读取成功");
    assert_eq!(got, msg);
}

#[tokio::test]
async fn read_message_exact_leaves_no_pending_bytes() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    let msg = Message::StreamConn { stream_id: 7 };
    write_message(&mut a, &msg).await.unwrap();
    // 紧跟一帧后追加原始字节（模拟 StreamConn 之后的裸流数据）
    a.write_all(&[0xDE, 0xAD]).await.unwrap();

    let got = read_message_exact(&mut b).await.expect("读取首帧");
    assert_eq!(got, msg);
    // 裸字节必须原样到达，不能被解码器吞掉
    let mut raw = [0u8; 2];
    b.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, [0xDE, 0xAD]);
}

#[tokio::test]
async fn read_message_reports_eof() {
    let (mut a, mut b) = tokio::io::duplex(64);
    let msg = Message::Heartbeat { timestamp_ms: 1 };
    write_message(&mut a, &msg).await.unwrap();
    drop(a); // 对端关闭
    let mut dec = FrameDecoder::new();
    // 第一条正常读出
    assert!(read_message(&mut b, &mut dec).await.is_ok());
    // 第二次应遇到 EOF
    let err = read_message(&mut b, &mut dec).await.unwrap_err();
    match err {
        ProtocolError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
        other => panic!("期望 Io(UnexpectedEof)，实际 {other:?}"),
    }
}
