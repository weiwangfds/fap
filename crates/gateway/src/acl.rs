//! ACL：隧道的 allowed_ips CIDR 匹配（M5a）。
//! 语义：列表为空 = 不限来源；否则来源 IP 必须命中至少一个 CIDR。

/// 检查 `ip` 是否被 `allowed` 允许。空列表 = 允许全部。
pub fn ip_allowed(ip: std::net::IpAddr, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    allowed.iter().any(|c| cidr_matches(ip, c))
}

/// 单条 CIDR 匹配。支持 IPv4 `a.b.c.d/len`、IPv6 `x::y/len`、裸 IP（/32 视为精确）。
pub fn cidr_matches(ip: std::net::IpAddr, cidr: &str) -> bool {
    let (addr_part, len_part) = match cidr.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (cidr, None),
    };
    let parsed: std::net::IpAddr = match addr_part.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    match (parsed, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(target)) => {
            let len = match len_part {
                Some(l) => match l.parse::<u8>() {
                    Ok(v) if v <= 32 => v,
                    _ => return false,
                },
                None => 32,
            };
            v4_in(net, target, len)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(target)) => {
            let len = match len_part {
                Some(l) => match l.parse::<u8>() {
                    Ok(v) if v <= 128 => v,
                    _ => return false,
                },
                None => 128,
            };
            v6_in(net, target, len)
        }
        _ => false, // v4/v6 家族不匹配
    }
}

fn v4_in(net: std::net::Ipv4Addr, target: std::net::Ipv4Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let n = u32::from(net);
    let t = u32::from(target);
    let mask = u32::MAX << (32 - len);
    (n & mask) == (t & mask)
}

fn v6_in(net: std::net::Ipv6Addr, target: std::net::Ipv6Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let n = u128::from(net);
    let t = u128::from(target);
    let mask = u128::MAX << (128 - len);
    (n & mask) == (t & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_list_allows_everything() {
        assert!(ip_allowed(v4("1.2.3.4"), &[]));
    }

    #[test]
    fn exact_ip_cidr() {
        assert!(ip_allowed(v4("10.0.0.5"), &["10.0.0.5".into()]));
        assert!(!ip_allowed(v4("10.0.0.6"), &["10.0.0.5".into()]));
    }

    #[test]
    fn cidr_range_matches() {
        assert!(ip_allowed(v4("192.168.1.77"), &["192.168.1.0/24".into()]));
        assert!(!ip_allowed(v4("192.168.2.77"), &["192.168.1.0/24".into()]));
    }

    #[test]
    fn multiple_cidrs_any_match() {
        let list = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
        assert!(ip_allowed(v4("10.1.2.3"), &list));
        assert!(ip_allowed(v4("192.168.5.5"), &list));
        assert!(!ip_allowed(v4("172.16.0.1"), &list));
    }

    #[test]
    fn zero_len_matches_all_v4() {
        assert!(ip_allowed(v4("8.8.8.8"), &["0.0.0.0/0".into()]));
    }

    #[test]
    fn malformed_cidr_never_matches() {
        assert!(!ip_allowed(v4("10.0.0.1"), &["not-a-cidr".into()]));
        assert!(!ip_allowed(v4("10.0.0.1"), &["10.0.0.0/40".into()]));
    }

    #[test]
    fn v6_matches_and_family_isolated() {
        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(ip_allowed(v6, &["fe80::/16".into()]));
        assert!(!ip_allowed(v6, &["10.0.0.0/8".into()]));
        assert!(!ip_allowed(v4("10.0.0.1"), &["fe80::/16".into()]));
    }
}