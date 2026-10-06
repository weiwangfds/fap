//! HMAC-SHA256 工具：用于 challenge-response 认证。
//! 计算 `HMAC(secret, nonce || ts_ms_be)`，定长 [u8; 32]。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::HMAC_BYTES;

type HmacSha256 = Hmac<Sha256>;

/// 用 32-byte 共享密钥对 nonce || ts 计算 HMAC-SHA256。
pub fn compute(secret: &[u8; HMAC_BYTES], nonce: &[u8; HMAC_BYTES], ts_ms: u64) -> [u8; HMAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 接受任意 key 长度");
    mac.update(nonce);
    mac.update(&ts_ms.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut sig = [0u8; HMAC_BYTES];
    sig.copy_from_slice(&out);
    sig
}

/// 用字符串 key 对任意域分隔消息计算 HMAC-SHA256（如 admin 会话令牌签名）。
pub fn compute_str_key(key: &str, parts: &[&[u8]]) -> [u8; HMAC_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC-SHA256 接受任意 key");
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut sig = [0u8; HMAC_BYTES];
    sig.copy_from_slice(&out);
    sig
}

/// 常量时间比较（防侧信道）。
pub fn constant_time_eq(a: &[u8; HMAC_BYTES], b: &[u8; HMAC_BYTES]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..HMAC_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_deterministic_and_distinct_for_inputs() {
        let key = [7u8; HMAC_BYTES];
        let n1 = [1u8; HMAC_BYTES];
        let n2 = [2u8; HMAC_BYTES];
        assert_eq!(compute(&key, &n1, 100), compute(&key, &n1, 100));
        assert_ne!(compute(&key, &n1, 100), compute(&key, &n1, 101));
        assert_ne!(compute(&key, &n1, 100), compute(&key, &n2, 100));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [1u8; HMAC_BYTES];
        let mut b = a;
        assert!(constant_time_eq(&a, &b));
        b[5] = 9;
        assert!(!constant_time_eq(&a, &b));
    }
}