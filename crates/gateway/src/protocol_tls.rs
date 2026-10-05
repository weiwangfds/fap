//! TLS ClientHello ServerName 提取（SNI 路由的最小解析）。
//! 完整 TLS 解析需要重型状态机；本模块只关心：首字节 0x16、TLS 1.x、Handshake=1、
//! ClientHello 内 extensions 中 server_name 列表的第一个 host_name。
//! 解析失败/未找到 → 返回 None。

/// 从 ClientHello 首字节中提取 SNI（服务器名）。buffer 不必完整。
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    // TLSRecord: type(1) version(2) length(2)
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return None;
    }
    let p = &buf[5..5 + rec_len];
    if p.is_empty() || p[0] != 0x01 {
        // Handshake type: client_hello = 1
        return None;
    }
    // Handshake: type(1) length(3) body
    let hs_len = u24(&p[1..4]) as usize;
    if p.len() < 4 + hs_len {
        return None;
    }
    let hello = &p[4..];
    // ClientHello: version(2) random(32) session_id(1+...) cipher_suites(2+...) compression(1+...)
    if hello.len() < 2 + 32 {
        return None;
    }
    let mut cur = &hello[2 + 32..];
    // session_id
    if cur.is_empty() {
        return None;
    }
    let sid_len = cur[0] as usize;
    cur = &cur[1 + sid_len..];
    // cipher_suites
    if cur.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = &cur[2 + cs_len..];
    // compression_methods
    if cur.is_empty() {
        return None;
    }
    let cm_len = cur[0] as usize;
    cur = &cur[1 + cm_len..];
    // extensions（optional）
    if cur.len() < 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = &cur[2..];
    if cur.len() < ext_len {
        return None;
    }
    let exts = &cur[..ext_len];
    parse_extensions_for_sni(exts)
}

fn parse_extensions_for_sni(buf: &[u8]) -> Option<String> {
    let mut p = buf;
    while p.len() >= 4 {
        let ext_type = u16::from_be_bytes([p[0], p[1]]);
        let ext_len = u16::from_be_bytes([p[2], p[3]]) as usize;
        if p.len() < 4 + ext_len {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name extension
            return parse_server_name_ext(&p[4..4 + ext_len]);
        }
        p = &p[4 + ext_len..];
    }
    None
}

fn parse_server_name_ext(buf: &[u8]) -> Option<String> {
    // ServerNameList: length(2) { ServerName: type(1) length(2) name(...) }*
    if buf.len() < 2 {
        return None;
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + total {
        return None;
    }
    let mut p = &buf[2..2 + total];
    while p.len() >= 3 {
        let name_type = p[0];
        let name_len = u16::from_be_bytes([p[1], p[2]]) as usize;
        if p.len() < 3 + name_len {
            return None;
        }
        if name_type == 0 {
            // host_name
            return std::str::from_utf8(&p[3..3 + name_len])
                .ok()
                .map(|s| s.to_string());
        }
        p = &p[3 + name_len..];
    }
    None
}

fn u24(b: &[u8]) -> u32 {
    if b.len() < 3 {
        return 0;
    }
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str) -> Vec<u8> {
        // 构造一个最小但合法的 ClientHello
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id length = 0
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]); // cipher_suites length=2, TLS_RSA_WITH_AES_256_CBC_SHA
        hello.push(0x01); // compression_methods length = 1
        hello.push(0x00); // null compression
        // extensions
        let mut ext = Vec::new();
        // server_name extension
        let mut sn_ext = Vec::new();
        sn_ext.push(0x00); // ServerNameList length high (placeholder)
        sn_ext.push(0x00); // low (placeholder)
        let sni_bytes = sni.as_bytes();
        let entry_len = 1 + 2 + sni_bytes.len(); // type + length + name
        sn_ext.push(0x00); // host_name type
        sn_ext.push(((entry_len - 3) >> 8) as u8);
        sn_ext.push(((entry_len - 3)) as u8);
        sn_ext.extend_from_slice(sni_bytes);
        let list_len = entry_len;
        sn_ext[0] = ((list_len) >> 8) as u8;
        sn_ext[1] = ((list_len) as u8);
        ext.extend_from_slice(&[0x00, 0x00]); // type = server_name
        let l = sn_ext.len();
        ext.extend_from_slice(&[(l >> 8) as u8, l as u8]);
        ext.extend_from_slice(&sn_ext);
        hello.extend_from_slice(&[(ext.len() >> 8) as u8, ext.len() as u8]);
        hello.extend_from_slice(&ext);

        // Handshake: type=1 + length(3) + body
        let mut handshake = Vec::new();
        handshake.push(0x01); // client_hello
        handshake.push((hello.len() >> 16) as u8);
        handshake.push((hello.len() >> 8) as u8);
        handshake.push(hello.len() as u8);
        handshake.extend_from_slice(&hello);

        // TLS record: type=0x16 version=0x0303 length
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&[(handshake.len() >> 8) as u8, handshake.len() as u8]);
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_simple_sni() {
        let buf = build_client_hello("example.com");
        assert_eq!(parse_sni(&buf), Some("example.com".to_string()));
    }

    #[test]
    fn returns_none_for_non_tls() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_sni(b""), None);
    }

    #[test]
    fn returns_none_for_truncated_record() {
        let mut buf = build_client_hello("x.test");
        buf.truncate(buf.len() - 10);
        assert_eq!(parse_sni(&buf), None, "截断应返回 None");
    }

    #[test]
    fn empty_buffer_yields_none() {
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x16]), None);
    }

    #[test]
    fn accepts_short_sni() {
        let buf = build_client_hello("a");
        assert_eq!(parse_sni(&buf), Some("a".to_string()));
    }

    #[test]
    fn wrong_record_type_is_rejected() {
        let mut buf = build_client_hello("x.test");
        buf[0] = 0x17; // app_data record, 不是 handshake
        assert_eq!(parse_sni(&buf), None);
    }
}