//! M5c-4：直连打洞骨架。
//!
//! 目标形态（设计对齐 RustDesk 的「并发竞速、中继回退」）：
//! 1. 双方各自收集候选地址（本机 IP + 经 STUN 得知的公网映射）
//! 2. 通过控制通道交换候选（PunchOffer/PunchAnswer）
//! 3. 双方同时向对方所有候选发 UDP 打洞包（ProbePacket）
//! 4. 任一候选在超时内收到回包 → 直连建立；全部失败 → 回退现有中继
//!
//! 本模块先落地「候选收集 + 探测包编解码」两块纯逻辑（可 TDD），
//! 交换协议与竞速调度属于数据面接线（依赖 M5c-3 的 Transport 切换）。


/// 候选地址类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// 本机/内网地址。
    Host,
    /// 经 STUN 探测得到的公网映射地址。
    ServerReflexive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub addr: std::net::SocketAddr,
    pub kind: CandidateKind,
}

/// 收集本机候选：通过「连接外部地址的 UDP socket 不实际发包，仅让内核选路」
/// 拿到本机出口 IP（无需第三方依赖）。端口用 socket 实际绑定的端口。
pub fn gather_host_candidates(remote: std::net::SocketAddr) -> Vec<Candidate> {
    let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    // connect 仅编程选路，不产生任何数据包
    if sock.connect(remote).is_err() {
        return Vec::new();
    }
    let Ok(local) = sock.local_addr() else {
        return Vec::new();
    };
    vec![Candidate {
        addr: local,
        kind: CandidateKind::Host,
    }]
}

/// UDP 打洞探测包：MAGIC(4) + nonce(8) + ts_ms(8)，定长 20 字节。
/// nonce 由发起方生成，响应方原样回带（证明双向可达）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePacket {
    pub nonce: u64,
    pub ts_ms: u64,
}

pub const PROBE_MAGIC: u32 = 0x46415021; // "FAP!"

impl ProbePacket {
    pub fn encode(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&PROBE_MAGIC.to_be_bytes());
        buf[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        buf[12..20].copy_from_slice(&self.ts_ms.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 20 {
            return None;
        }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != PROBE_MAGIC {
            return None;
        }
        Some(Self {
            nonce: u64::from_be_bytes(buf[4..12].try_into().ok()?),
            ts_ms: u64::from_be_bytes(buf[12..20].try_into().ok()?),
        })
    }
}

/// 响应包 = 同一 nonce + 响应标记（ts 置 0 区分）。
impl ProbePacket {
    pub fn reply(&self) -> ProbePacket {
        ProbePacket {
            nonce: self.nonce,
            ts_ms: 0,
        }
    }

    pub fn is_reply(&self) -> bool {
        self.ts_ms == 0
    }
}

/// 打洞尝试的纯调度决策：给定「已收到的回包数 / 截止时间」，判定继续/成功/放弃。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchOutcome {
    /// 继续向剩余候选发包。
    Continue,
    /// 至少一个候选双向可达，直连可用。
    Succeeded,
    /// 超时，回退中继。
    Fallback,
}

pub fn evaluate(replies: usize, deadline_passed: bool) -> PunchOutcome {
    if replies > 0 {
        PunchOutcome::Succeeded
    } else if deadline_passed {
        PunchOutcome::Fallback
    } else {
        PunchOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_packet_round_trips() {
        let p = ProbePacket { nonce: 42, ts_ms: 123456 };
        let buf = p.encode();
        assert_eq!(buf.len(), 20);
        assert_eq!(ProbePacket::decode(&buf), Some(p));
    }

    #[test]
    fn probe_packet_rejects_wrong_magic_and_length() {
        let mut buf = ProbePacket { nonce: 1, ts_ms: 1 }.encode();
        buf[0] ^= 0xFF;
        assert_eq!(ProbePacket::decode(&buf), None);
        assert_eq!(ProbePacket::decode(&buf[..19]), None);
        assert_eq!(ProbePacket::decode(&[]), None);
    }

    #[test]
    fn reply_carries_nonce_and_is_marked() {
        let p = ProbePacket { nonce: 7, ts_ms: 9 };
        let r = p.reply();
        assert_eq!(r.nonce, 7);
        assert!(r.is_reply());
        assert!(!p.is_reply());
    }

    #[test]
    fn host_candidates_have_bind_port() {
        // 连接一个测试网段地址（不会真发包）
        let cands = gather_host_candidates("192.0.2.1:9".parse().unwrap());
        assert!(!cands.is_empty(), "应至少得到一个 Host 候选");
        assert_eq!(cands[0].kind, CandidateKind::Host);
        assert!(cands[0].addr.port() > 0, "端口应为内核分配的非零端口");
    }

    #[test]
    fn outcome_schedule() {
        assert_eq!(evaluate(0, false), PunchOutcome::Continue);
        assert_eq!(evaluate(1, false), PunchOutcome::Succeeded);
        assert_eq!(evaluate(0, true), PunchOutcome::Fallback);
        assert_eq!(evaluate(2, true), PunchOutcome::Succeeded, "已有回包则成功优先于超时");
    }

    #[test]
    fn magic_is_fap_bang() {
        assert_eq!(&PROBE_MAGIC.to_be_bytes(), b"FAP!");
    }

    #[test]
    fn ip_addr_family_independent() {
        // Candidate 对 v4/v6 都成立（编译期即可保证，这里做行为占位断言）
        let c = Candidate {
            addr: "[::1]:9999".parse().unwrap(),
            kind: CandidateKind::Host,
        };
        assert!(c.addr.is_ipv6());
        let _ip = c.addr.ip();
    }
}