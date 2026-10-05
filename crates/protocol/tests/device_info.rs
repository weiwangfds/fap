//! 设备元信息字段在 Register 中的序列化（参考 Orbien Login 的字段形状）。

use fap_protocol::{DeviceInfo, Message};

#[test]
fn device_info_default_serialization() {
    let info = DeviceInfo {
        hostname: "laptop-1".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        version: "0.1.0".into(),
        user: "alice".into(),
    };
    let v = serde_json::to_value(&info).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "hostname": "laptop-1",
            "os": "linux",
            "arch": "x86_64",
            "version": "0.1.0",
            "user": "alice",
        })
    );
}

#[test]
fn register_carries_device_info() {
    let info = DeviceInfo {
        hostname: "nas".into(),
        os: "freebsd".into(),
        arch: "aarch64".into(),
        version: "0.2.3".into(),
        user: String::new(),
    };
    let msg = Message::Register {
        device_id: "dev1".into(),
        token: "secret".into(),
        device_info: Some(info.clone()),
        tunnels: vec![],
        pk: None,
    };
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "type": "register",
            "device_id": "dev1",
            "token": "secret",
            "device_info": {
                "hostname": "nas",
                "os": "freebsd",
                "arch": "aarch64",
                "version": "0.2.3",
                "user": "",
            },
            "tunnels": [],
            "pk": null,
        })
    );
}

#[test]
fn register_backward_compatible_when_device_info_missing() {
    // M2 之前的 Register 没有 device_info / pk，必须兼容
    let legacy = serde_json::json!({
        "type": "register",
        "device_id": "old",
        "token": "old",
        "tunnels": []
    });
    let msg: Message = serde_json::from_value(legacy).unwrap();
    let Message::Register { device_info, pk, .. } = msg else {
        panic!("unreachable");
    };
    assert!(device_info.is_none(), "旧 JSON 反序列化应保留 None");
    assert!(pk.is_none(), "旧 JSON 反序列化应保留 None");
}

#[test]
fn roundtrip_register_with_device_info() {
    let mut dec = fap_protocol::FrameDecoder::new();
    let msg = Message::Register {
        device_id: "dev1".into(),
        token: "secret".into(),
        device_info: Some(DeviceInfo {
            hostname: "h".into(),
            os: "macos".into(),
            arch: "aarch64".into(),
            version: "0.1.0".into(),
            user: "bob".into(),
        }),
        tunnels: vec![],
        pk: None,
    };
    let bytes = fap_protocol::encode(&msg).unwrap();
    dec.feed(&bytes);
    assert_eq!(dec.next_message().unwrap().unwrap(), msg);
}