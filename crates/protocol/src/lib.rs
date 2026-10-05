//! fap-protocol：agent 与 gateway 之间的控制协议。
//!
//! 帧格式: `[长度 u32 BE][类型 u8][JSON 载荷]`，其中长度字段 = 类型字节 + 载荷长度。
//! 类型字节用于分发与向前兼容校验；JSON 载荷自描述（含 `type` 字段）。

use std::io;

pub mod config;
pub mod hmac;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 单帧长度上限（含类型字节），防止恶意或损坏的长度字段撑爆内存。
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;
/// 长度字段宽度（u32 BE）。
pub const LEN_FIELD: usize = 4;
/// 定长前缀总宽：长度字段 + 类型字节。
pub const HEADER_LEN: usize = LEN_FIELD + 1;

pub const MSG_REGISTER: u8 = 1;
pub const MSG_REGISTER_ACK: u8 = 2;
pub const MSG_HEARTBEAT: u8 = 3;
pub const MSG_HEARTBEAT_ACK: u8 = 4;
pub const MSG_OPEN_STREAM: u8 = 5;
pub const MSG_STREAM_CONN: u8 = 6;
pub const MSG_CONFIG_PUSH: u8 = 7;
pub const MSG_CONFIG_ACK: u8 = 8;
pub const MSG_ACCESS_REQUEST: u8 = 9;
pub const MSG_AUTH_CHALLENGE: u8 = 10;
pub const MSG_AUTH_CHALLENGE_RESP: u8 = 11;
/// HMAC 摘要长度（SHA-256 = 32 字节）。
pub const HMAC_BYTES: usize = 32;

/// 注册应答中带回的实际设备信息（agent 上报 → 控制台展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeviceInfo {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub version: String,
    /// 登录用户名（可选）。
    #[serde(default)]
    pub user: String,
}

/// 一条隧道的定义。
///
/// 对外暴露方式（可组合，至少其一）：
/// - `listen_port > 0`：独占网关上的一个端口（M1 方式）；
/// - `host` / `path`：在共享 HTTP 端口上按域名/路径后缀路由（M3）；
/// - `sni`：在共享 TLS 端口上按 SNI 直通路由（M3）；
/// - `access_token`：允许通过访问器（fap-access）按隧道名接入（M4）。
///
/// 安全选项（M5）：`allowed_ips` 为空表示不限来源；`max_concurrent` 限制并发连接数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TunnelConfig {
    /// 隧道标识，同一设备内唯一。
    pub tunnel_id: String,
    /// 独占监听端口；0 = 不占用独立端口。
    #[serde(default)]
    pub listen_port: u16,
    /// 内网真实服务地址。
    pub target_host: String,
    pub target_port: u16,
    /// 共享 HTTP 端口上的域名路由（精确或 `*.example.com` 通配）。
    #[serde(default)]
    pub host: Option<String>,
    /// 共享 HTTP 端口上的路径前缀路由，如 `/web`。
    #[serde(default)]
    pub path: Option<String>,
    /// 共享 TLS 端口上的 SNI 直通路由。
    #[serde(default)]
    pub sni: Option<String>,
    /// 访问器接入令牌；None = 禁止访问器接入。
    #[serde(default)]
    pub access_token: Option<String>,
    /// 允许访问的来源 CIDR 列表；空 = 不限。
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// 最大并发用户连接数；None = 不限。
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

/// 注册应答中带回的实际监听信息（含自动分配的端口）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub tunnel_id: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Register {
        device_id: String,
        token: String,
        /// 设备元信息（hostname/os/arch/version/user），agent 上报到控制台展示。
        #[serde(default)]
        device_info: Option<DeviceInfo>,
        /// agent 的 Ed25519 公钥（M2.5d）；None 表示未启用 PK 模式。
        #[serde(default)]
        pk: Option<String>,
        tunnels: Vec<TunnelConfig>,
    },
    RegisterAck {
        ok: bool,
        error: Option<String>,
        /// 网关数据平面的端口（agent 用它回连建立数据连接）。
        data_port: u16,
        /// 各隧道实际监听的端口（独占端口方式）。
        listeners: Vec<ListenerInfo>,
        /// 网关最终生效的隧道全集（可能来自控制台覆盖），agent 以此更新本地路由表。
        #[serde(default)]
        applied_tunnels: Vec<TunnelConfig>,
    },
    Heartbeat {
        timestamp_ms: u64,
    },
    HeartbeatAck {
        timestamp_ms: u64,
    },
    /// 网关 → agent：有用户访问，请为该流建立数据连接。
    OpenStream {
        stream_id: u64,
        tunnel_id: String,
    },
    /// agent → 网关（数据连接上的首帧）：本连接承载哪个流，其后转为裸字节流。
    StreamConn {
        stream_id: u64,
    },
    /// 网关 → agent：控制台下发了新的隧道全集，请更新本地路由表。
    ConfigPush {
        revision: u64,
        tunnels: Vec<TunnelConfig>,
    },
    /// agent → 网关：配置已应用。
    ConfigAck {
        ok: bool,
        error: Option<String>,
        revision: u64,
    },
    /// 访问器（fap-access）→ 网关：请求接入某条隧道，其后转为裸字节流。
    AccessRequest {
        tunnel_id: String,
        token: String,
    },
    /// 网关 → agent：发送 nonce+ts 挑战。
    AuthChallenge {
        nonce: [u8; HMAC_BYTES],
        ts_ms: u64,
    },
    /// agent → 网关：HMAC-SHA256(secret, nonce || ts) 的前 32 字节。
    AuthChallengeResp {
        sig: [u8; HMAC_BYTES],
        ts_ms: u64,
    },
}

impl Message {
    /// 消息的类型字节。
    pub fn kind(&self) -> u8 {
        match self {
            Message::Register { .. } => MSG_REGISTER,
            Message::RegisterAck { .. } => MSG_REGISTER_ACK,
            Message::Heartbeat { .. } => MSG_HEARTBEAT,
            Message::HeartbeatAck { .. } => MSG_HEARTBEAT_ACK,
            Message::OpenStream { .. } => MSG_OPEN_STREAM,
            Message::StreamConn { .. } => MSG_STREAM_CONN,
            Message::ConfigPush { .. } => MSG_CONFIG_PUSH,
            Message::ConfigAck { .. } => MSG_CONFIG_ACK,
            Message::AccessRequest { .. } => MSG_ACCESS_REQUEST,
            Message::AuthChallenge { .. } => MSG_AUTH_CHALLENGE,
            Message::AuthChallengeResp { .. } => MSG_AUTH_CHALLENGE_RESP,
        }
    }

    /// 类型字节反查名称；未知类型返回 None。
    pub fn kind_name(kind: u8) -> Option<&'static str> {
        Some(match kind {
            MSG_REGISTER => "register",
            MSG_REGISTER_ACK => "register_ack",
            MSG_HEARTBEAT => "heartbeat",
            MSG_HEARTBEAT_ACK => "heartbeat_ack",
            MSG_OPEN_STREAM => "open_stream",
            MSG_STREAM_CONN => "stream_conn",
            MSG_CONFIG_PUSH => "config_push",
            MSG_CONFIG_ACK => "config_ack",
            MSG_ACCESS_REQUEST => "access_request",
            MSG_AUTH_CHALLENGE => "auth_challenge",
            MSG_AUTH_CHALLENGE_RESP => "auth_challenge_resp",
            _ => return None,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("帧长度 {0} 超过上限 {1}")]
    FrameTooLarge(usize, usize),
    #[error("空帧（长度为 0）")]
    EmptyFrame,
    #[error("未知消息类型字节 {0}")]
    UnknownMessageType(u8),
    #[error("载荷反序列化失败: {0}")]
    BadPayload(#[from] serde_json::Error),
    #[error("i/o 错误: {0}")]
    Io(#[from] io::Error),
}

/// 编码一条消息为完整帧。
pub fn encode(msg: &Message) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(msg)?;
    let len = payload.len() + 1;
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len, MAX_FRAME_LEN));
    }
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    buf.push(msg.kind());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// 流式帧解码器：喂入任意分片的字节，按完整帧取出消息。
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入新到达的字节。
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// 尝试取出下一条完整消息；数据不足时返回 `Ok(None)`。
    /// 返回 Err 表示流已损坏，调用方应断开连接。
    pub fn next_message(&mut self) -> Result<Option<Message>, ProtocolError> {
        if self.buf.len() < LEN_FIELD {
            return Ok(None);
        }
        let len =
            u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len == 0 {
            return Err(ProtocolError::EmptyFrame);
        }
        if len > MAX_FRAME_LEN {
            return Err(ProtocolError::FrameTooLarge(len, MAX_FRAME_LEN));
        }
        if self.buf.len() < LEN_FIELD + len {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buf.drain(..LEN_FIELD + len).collect();
        let kind = frame[LEN_FIELD];
        if Message::kind_name(kind).is_none() {
            return Err(ProtocolError::UnknownMessageType(kind));
        }
        let msg: Message = serde_json::from_slice(&frame[HEADER_LEN..])?;
        Ok(Some(msg))
    }

    /// 缓冲区内待处理的字节数。
    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }
}

/// 异步写一条消息。
pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &Message,
) -> Result<(), ProtocolError> {
    let bytes = encode(msg)?;
    w.write_all(&bytes).await?;
    Ok(())
}

/// 精确读取一帧（基于 read_exact），保证不吞掉帧后的任何原始字节。
/// 用于数据连接的首帧（StreamConn）：读完帧后连接即转为裸字节流。
pub async fn read_message_exact<R: AsyncRead + Unpin>(r: &mut R) -> Result<Message, ProtocolError> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len, MAX_FRAME_LEN));
    }
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body).await?;
    let kind = header[LEN_FIELD];
    if Message::kind_name(kind).is_none() {
        return Err(ProtocolError::UnknownMessageType(kind));
    }
    let msg: Message = serde_json::from_slice(&body)?;
    Ok(msg)
}

/// 用解码器持续读取（允许跨 read 缓冲）。
/// 用于控制连接——整条连接都由消息帧组成。
pub async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    dec: &mut FrameDecoder,
) -> Result<Message, ProtocolError> {
    loop {
        if let Some(msg) = dec.next_message()? {
            return Ok(msg);
        }
        let mut chunk = [0u8; 8192];
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Err(ProtocolError::Io(io::Error::from(
                io::ErrorKind::UnexpectedEof,
            )));
        }
        dec.feed(&chunk[..n]);
    }
}
