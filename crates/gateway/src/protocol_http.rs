//! HTTP/1.1 反代解析：足够支持「按 Host/Path 路由 + hop-by-hop 头清理」。
//! 复用 httparse 做请求头解析，避免自带解析器。

use std::collections::BTreeMap;

/// 解析后的请求头部（无 body）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub host: String,
    /// 小写名；大小写不敏感键。
    pub headers: BTreeMap<String, String>,
}

/// 从字节流中解析 HTTP/1.1 请求头；未完整（缺 `\r\n\r\n`）返回 Ok(None)。
pub fn parse_request_head(buf: &[u8]) -> Result<Option<RequestHead>, ParseError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(_consumed)) => {
            let method = req
                .method
                .ok_or(ParseError::Malformed)?
                .to_string();
            let path = req
                .path
                .ok_or(ParseError::Malformed)?
                .to_string();
            let mut host = String::new();
            let mut map: BTreeMap<String, String> = BTreeMap::new();
            for h in req.headers.iter() {
                let key = h.name.to_ascii_lowercase();
                let val = String::from_utf8_lossy(h.value).into_owned();
                if key == "host" {
                    host = val;
                } else {
                    map.insert(key, val);
                }
            }
            Ok(Some(RequestHead {
                method,
                path,
                host,
                headers: map,
            }))
        }
        Err(_) => Err(ParseError::Malformed),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
}

/// 清理 hop-by-hop 头（RFC 7230 §6.1）：
/// 1. 删除以下 7 个固定头：`Connection`、`Keep-Alive`、`Proxy-Authenticate`、
///    `Proxy-Authorization`、`TE`、`Trailer`、`Transfer-Encoding`。
/// 2. 删除 `Connection` 字段值里列出的所有头。
pub fn strip_hop_by_hop(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    const FORBIDDEN: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ];
    // 收集 Connection 字段值里列出的额外 hop-by-hop 头
    let mut extras: Vec<String> = Vec::new();
    // 同时看大小写两种 key 入参（已 normalize 时小写、未 normalize 时保持原大小写）
    for key in ["connection", "Connection", "CONNECTION"] {
        if let Some(conn) = headers.get(key) {
            for token in conn.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    extras.push(t);
                }
            }
            break;
        }
    }
    let mut out = BTreeMap::new();
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if FORBIDDEN.contains(&lk.as_str()) {
            continue;
        }
        if extras.iter().any(|e| e == &lk) {
            continue;
        }
        out.insert(lk, v.clone());
    }
    out
}

/// 序列化头：每行 `Name: Value\r\n`，BTreeMap 顺序稳定。
pub fn write_headers(headers: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len() * 32);
    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_get_request() {
        let req = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
        let r = parse_request_head(req).unwrap().unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/");
        assert_eq!(r.host, "a.test");
    }

    #[test]
    fn parses_request_with_multiple_headers() {
        let req = b"POST /api/users HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\nUser-Agent: curl/7.0\r\n\r\n";
        let r = parse_request_head(req).unwrap().unwrap();
        assert_eq!(r.path, "/api/users");
        assert_eq!(r.headers.get("content-type").unwrap(), "application/json");
        assert_eq!(r.headers.get("user-agent").unwrap(), "curl/7.0");
    }

    #[test]
    fn returns_none_for_partial() {
        let r = parse_request_head(b"GET / HTTP/1.1\r\nHost: a.test\r\n");
        assert!(matches!(r, Ok(None)));
    }

    #[test]
    fn returns_err_for_garbage() {
        assert!(parse_request_head(b"\0\0\0garbage").is_err());
    }

    #[test]
    fn strip_hop_by_hop_removes_seven_fixed_headers() {
        let mut h = BTreeMap::new();
        for k in [
            "Connection", "Keep-Alive", "Proxy-Authenticate",
            "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding",
        ] {
            h.insert(k.to_string(), "x".to_string());
        }
        h.insert("Host".to_string(), "a.test".to_string());
        let out = strip_hop_by_hop(&h);
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("keep-alive"));
        assert!(!out.contains_key("proxy-authenticate"));
        assert!(!out.contains_key("proxy-authorization"));
        assert!(!out.contains_key("te"));
        assert!(!out.contains_key("trailer"));
        assert!(!out.contains_key("transfer-encoding"));
        assert!(out.contains_key("host"));
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_listed_tokens() {
        let mut h = BTreeMap::new();
        h.insert("Connection".to_string(), "X-Custom, X-Other".to_string());
        h.insert("x-custom".to_string(), "1".to_string());
        h.insert("x-other".to_string(), "2".to_string());
        h.insert("x-keep".to_string(), "3".to_string());
        let out = strip_hop_by_hop(&h);
        assert!(!out.contains_key("connection"));
        assert!(!out.contains_key("x-custom"));
        assert!(!out.contains_key("x-other"));
        assert!(out.contains_key("x-keep"));
    }

    #[test]
    fn write_headers_emits_stable_order() {
        let mut h = BTreeMap::new();
        h.insert("Z".into(), "z".into());
        h.insert("A".into(), "a".into());
        let out = write_headers(&h);
        let s = String::from_utf8_lossy(&out);
        assert!(s.find("A:").unwrap() < s.find("Z:").unwrap(), "BTreeMap 必须按 key 排序");
    }
}