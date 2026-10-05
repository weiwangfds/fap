//! M2.5c：HMAC-SHA256 challenge-response 协议形状锁定。

use fap_protocol::{
    encode, FrameDecoder, Message, MSG_AUTH_CHALLENGE, MSG_AUTH_CHALLENGE_RESP,
};

#[test]
fn hmac_messages_have_distinct_kind_bytes() {
    let ch = Message::AuthChallenge {
        nonce: [0u8; 32],
        ts_ms: 1,
    };
    let resp = Message::AuthChallengeResp {
        sig: [0u8; 32],
        ts_ms: 1,
    };
    assert_eq!(ch.kind(), MSG_AUTH_CHALLENGE);
    assert_eq!(resp.kind(), MSG_AUTH_CHALLENGE_RESP);
    assert_ne!(ch.kind(), resp.kind());
}

#[test]
fn hmac_messages_roundtrip() {
    let mut nonce = [0u8; 32];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let mut sig = [0u8; 32];
    sig[0] = 0xab;
    sig[31] = 0xcd;
    for msg in [
        Message::AuthChallenge {
            nonce,
            ts_ms: 42,
        },
        Message::AuthChallengeResp { sig, ts_ms: 42 },
    ] {
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes[4], msg.kind());
        let mut dec = FrameDecoder::new();
        dec.feed(&bytes);
        assert_eq!(dec.next_message().unwrap().unwrap(), msg);
    }
}

#[test]
fn hmac_challenge_serde_shape() {
    let ch = Message::AuthChallenge {
        nonce: [1u8; 32],
        ts_ms: 1700000000000,
    };
    let v = serde_json::to_value(&ch).unwrap();
    let nonce_arr: serde_json::Value =
        serde_json::Value::Array((0..32).map(|_| serde_json::json!(1u8)).collect());
    assert_eq!(
        v,
        serde_json::json!({"type": "auth_challenge", "nonce": nonce_arr, "ts_ms": 1700000000000u64})
    );
    let resp = Message::AuthChallengeResp {
        sig: [2u8; 32],
        ts_ms: 1700000000000,
    };
    let v = serde_json::to_value(&resp).unwrap();
    let sig_arr: serde_json::Value =
        serde_json::Value::Array((0..32).map(|_| serde_json::json!(2u8)).collect());
    assert_eq!(
        v,
        serde_json::json!({"type": "auth_challenge_resp", "sig": sig_arr, "ts_ms": 1700000000000u64})
    );
}