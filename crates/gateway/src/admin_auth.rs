//! M5b：admin 会话令牌 —— HMAC 签名的短期凭证。
//!
//! 格式：`<expiry_ms_hex>.<hmac_hex>`，hmac = HMAC-SHA256(admin_token, "fap-admin-session:" || expiry_ms_be)。
//! 主令牌（admin_token）仍可直接作为 Bearer 使用（服务端部署场景）；
//! 浏览器控制台通过 POST /api/auth/login 换取会话令牌，避免主令牌长期驻留 localStorage。

use fap_protocol::hmac;

const SESSION_PREFIX: &[u8] = b"fap-admin-session:";
const HMAC_BYTES: usize = 32;

/// 签发会话令牌：`<expiry_ms_hex>.<sig_hex>`。
pub fn issue_session(admin_token: &str, now_ms: u64, ttl_ms: u64) -> String {
    let expiry = now_ms.saturating_add(ttl_ms);
    let sig = sign(admin_token, expiry);
    format!("{expiry:x}.{}", sig_hex(&sig))
}

/// 验证会话令牌：签名正确且未过期。主令牌本身不在此验证（中间件并行支持）。
pub fn verify_session(admin_token: &str, token: &str, now_ms: u64) -> bool {
    let Some((expiry_hex, sig_hex)) = token.split_once('.') else {
        return false;
    };
    let Ok(expiry) = u64::from_str_radix(expiry_hex, 16) else {
        return false;
    };
    if expiry <= now_ms {
        return false;
    }
    let Ok(sig) = decode_hex32(sig_hex) else {
        return false;
    };
    hmac::constant_time_eq(&sign(admin_token, expiry), &sig)
}

fn sign(admin_token: &str, expiry_ms: u64) -> [u8; HMAC_BYTES] {
    hmac::compute_str_key(admin_token, &[SESSION_PREFIX, &expiry_ms.to_be_bytes()])
}

fn sig_hex(sig: &[u8; HMAC_BYTES]) -> String {
    sig.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex32(s: &str) -> Result<[u8; HMAC_BYTES], ()> {
    if s.len() != HMAC_BYTES * 2 {
        return Err(());
    }
    let mut out = [0u8; HMAC_BYTES];
    for i in 0..HMAC_BYTES {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "master-secret";

    #[test]
    fn issued_token_verifies() {
        let t = issue_session(KEY, 1_000_000, 60_000);
        assert!(verify_session(KEY, &t, 1_000_000));
        assert!(verify_session(KEY, &t, 1_059_999));
    }

    #[test]
    fn expired_token_rejected() {
        let t = issue_session(KEY, 1_000_000, 60_000);
        assert!(!verify_session(KEY, &t, 1_060_000), "到期即拒");
        assert!(!verify_session(KEY, &t, 2_000_000));
    }

    #[test]
    fn wrong_key_rejected() {
        let t = issue_session(KEY, 1_000_000, 60_000);
        assert!(!verify_session("other-key", &t, 1_000_000));
    }

    #[test]
    fn tampered_expiry_rejected() {
        let t = issue_session(KEY, 1_000_000, 60_000);
        // 把 expiry 改大：签名对不上
        let (_, sig) = t.split_once('.').unwrap();
        let forged = format!("{:x}.{}", u64::MAX, sig);
        assert!(!verify_session(KEY, &forged, 1_000_000));
    }

    #[test]
    fn garbage_tokens_rejected() {
        assert!(!verify_session(KEY, "", 0));
        assert!(!verify_session(KEY, "no-dot", 0));
        assert!(!verify_session(KEY, "zz.sig", 0));
        assert!(!verify_session(KEY, "10.zz", 0));
    }
}
