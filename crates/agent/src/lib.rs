//! fap 客户端核心：注册会话、心跳、开流处理、重连。

pub mod local_ui;
pub mod runtime;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fap_protocol::TunnelConfig;

/// 客户端运行配置。
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// 网关控制面地址（host:port）。
    pub server_addr: String,
    pub device_id: String,
    pub token: String,
    /// 登录用户名（展示用）。
    #[allow(dead_code)]
    pub user: String,
    /// Ed25519 公钥十六进制字符串（M2.5d）。
    pub pk: Option<String>,
    pub tunnels: Vec<TunnelConfig>,
    pub heartbeat_interval: Duration,
    pub connect_timeout: Duration,
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        })
}

/// 重连退避：指数增长、封顶、可重置。
pub struct Backoff {
    current: Duration,
    max: Duration,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("隧道规格格式应为 NAME:PORT:TARGET_HOST:TARGET_PORT，实际: {0}")]
    BadFormat(String),
    #[error("端口无效: {0}")]
    BadPort(String),
    #[error("隧道名不能为空")]
    EmptyName,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            current: base,
            max,
        }
    }

    /// 返回本次等待时长，并推进到下一档。
    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        self.current = std::cmp::min(self.current * 2, self.max);
        d
    }

    pub fn reset(&mut self, base: Duration) {
        self.current = base;
    }
}

/// 解析 `NAME:PORT:TARGET_HOST:TARGET_PORT` 形式的隧道规格。
pub fn parse_tunnel_spec(spec: &str) -> Result<TunnelConfig, SpecError> {    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 4 {
        return Err(SpecError::BadFormat(spec.to_string()));
    }
    let tunnel_id = parts[0];
    if tunnel_id.is_empty() {
        return Err(SpecError::EmptyName);
    }
    let target_host = parts[2];
    if target_host.is_empty() {
        return Err(SpecError::BadFormat(spec.to_string()));
    }
    let listen_port: u16 = parts[1]
        .parse()
        .map_err(|_| SpecError::BadPort(parts[1].to_string()))?;
    let target_port: u16 = parts[3]
        .parse()
        .map_err(|_| SpecError::BadPort(parts[3].to_string()))?;
    Ok(TunnelConfig {
        tunnel_id: tunnel_id.to_string(),
        listen_port,
        target_host: target_host.to_string(),
        target_port,
        ..Default::default()
    })
}

/// 运行一次完整会话：连接 → 注册 → 心跳 → 处理开流，直到控制连接结束。
/// `status` 供本地管理页读取（可传 None 不收集）。
pub async fn run_agent_session_with_status(
    cfg: AgentConfig,
    status: Option<Arc<runtime::RuntimeStatus>>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use fap_protocol::{read_message, write_message, FrameDecoder, Message};
    use tokio::net::TcpStream;

    let connect =
        tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&cfg.server_addr)).await;
    let mut stream = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            if let Some(st) = &status {
                st.set_last_error(format!("连接网关失败: {e}"));
            }
            return Err(anyhow::Error::new(e).context(format!("连接网关 {} 失败", cfg.server_addr)));
        }
        Err(_) => anyhow::bail!("连接网关 {} 超时", cfg.server_addr),
    };

    write_message(
        &mut stream,
        &Message::Register {
            device_id: cfg.device_id.clone(),
            token: cfg.token.clone(),
            device_info: Some(fap_protocol::DeviceInfo {
                hostname: hostname(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                user: cfg.user.clone(),
            }),
            pk: cfg.pk.clone(),
            tunnels: cfg.tunnels.clone(),
        },
    )
    .await?;

    let mut dec = FrameDecoder::new();
    let ack = read_message(&mut stream, &mut dec).await?;
    let Message::RegisterAck {
        ok,
        error,
        data_port,
        ..
    } = ack
    else {
        anyhow::bail!("期望 RegisterAck，实际 {ack:?}");
    };
    if !ok {
        if let Some(st) = &status {
            st.set_last_error(format!("注册被拒绝: {}", error.clone().unwrap_or_default()));
        }
        anyhow::bail!("注册被拒绝: {}", error.unwrap_or_default());
    }
    if let Some(st) = &status {
        st.set_registered(true);
        st.set_tunnels(cfg.tunnels.clone());
        st.set_last_error_clear();
    }

    let server: std::net::SocketAddr = cfg
        .server_addr
        .parse()
        .context("server_addr 不是合法的 host:port")?;
    let data_addr = std::net::SocketAddr::new(server.ip(), data_port);

    // M5c-2：预热数据连接池 —— 注册成功后立即建 N 条空闲 data 连接，
    // 每条只写一帧 StreamConn(stream_id=0) 占位（或静默等待）让网关侧持有 TcpStream。
    // 注：StreamConn 首帧带 stream_id=0 在网关 matcher.complete() 处无等待者，会被关闭。
    // 更稳的做法：agent 等 OpenStream 来时再写；空闲时连接不写首帧也不读——直接挂到池里。
    // 见 handle_stream 的 conn_id > 0 分支。
    let data_port_for_pool = data_addr;
    let pool_st = status.clone();
    tokio::spawn(async move {
        for _ in 0..4 {
            match tokio::net::TcpStream::connect(data_port_for_pool).await {
                Ok(s) => {
                    if let Some(st) = &pool_st {
                        st.pool_push(s);
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 本会话的隧道表：RegisterAck.applied_tunnels 与 ConfigPush 都会整体替换它
    let tunnels = {
        let map: HashMap<String, TunnelConfig> = cfg
            .tunnels
            .iter()
            .map(|t| (t.tunnel_id.clone(), t.clone()))
            .collect();
        Arc::new(std::sync::RwLock::new(map))
    };
    tracing::info!(
        "设备 {} 注册成功，数据面 {data_addr}，隧道 {:?}",
        cfg.device_id,
        cfg.tunnels
    );

    let (mut rh, mut wh) = stream.into_split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(64);

    // 心跳任务
    let hb_tx = tx.clone();
    let interval = cfg.heartbeat_interval;
    let hb = tokio::spawn(async move {
        let mut tk = tokio::time::interval(interval);
        tk.tick().await; // 消耗立即触发的首拍
        loop {
            tk.tick().await;
            if hb_tx
                .send(Message::Heartbeat {
                    timestamp_ms: now_ms(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // 下行任务：tx 通道 → 控制连接
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_message(&mut wh, &msg).await.is_err() {
                break;
            }
        }
    });

    // 读循环：处理网关的开流请求与配置下发
    let read_result: anyhow::Result<()> = loop {
        match read_message(&mut rh, &mut dec).await {
            Ok(Message::OpenStream {
                stream_id,
                tunnel_id,
                conn_id,
            }) => {
                let target = tunnels.read().unwrap().get(&tunnel_id).cloned();
                let Some(target) = target else {
                    tracing::warn!("收到未知隧道 {tunnel_id} 的开流请求，忽略");
                    continue;
                };
                let da = data_addr;
                let st = status.clone();
                tokio::spawn(async move {
                    if let Some(st) = &st {
                        st.stream_opened();
                    }
                    handle_stream(stream_id, da, target, conn_id, st).await;
                    if let Some(st) = &st {
                        st.stream_closed();
                    }
                });
            }
            Ok(Message::ConfigPush {
                revision,
                tunnels: new_tunnels,
            }) => {
                if let Some(st) = &status {
                    st.set_tunnels(new_tunnels.clone());
                }
                *tunnels.write().unwrap() = new_tunnels
                    .iter()
                    .map(|t| (t.tunnel_id.clone(), t.clone()))
                    .collect();
                tracing::info!(
                    "已应用控制台配置 rev={revision}，隧道: {:?}",
                    new_tunnels
                        .iter()
                        .map(|t| t.tunnel_id.clone())
                        .collect::<Vec<_>>()
                );
                let _ = tx
                    .send(Message::ConfigAck {
                        ok: true,
                        error: None,
                        revision,
                    })
                    .await;
            }
            Ok(_) => {}
            Err(e) => {
                if let Some(st) = &status {
                    st.set_last_error(format!("控制连接结束: {e}"));
                    st.set_registered(false);
                }
                break Err(anyhow::Error::new(e).context("控制连接结束"));
            }
        }
    };

    hb.abort();
    writer.abort();
    read_result
}

/// 兼容入口：不收集运行时状态的会话。
pub async fn run_agent_session(cfg: AgentConfig) -> anyhow::Result<()> {
    run_agent_session_with_status(cfg, None).await
}

/// 为一条用户流建立数据连接：回连网关 → 声明流 ID → 与内网真实服务对接。
/// `conn_id = 0` 走原路径（拨号新数据连接）；
/// `conn_id > 0` 从 `status.data_pool` 取对应连接（M5c-2 启用后）。
async fn handle_stream(
    stream_id: u64,
    data_addr: std::net::SocketAddr,
    target: TunnelConfig,
    conn_id: u32,
    status: Option<Arc<runtime::RuntimeStatus>>,
) {
    use fap_protocol::{write_message, Message};

    let mut data: Option<tokio::net::TcpStream> = None;
    if conn_id != 0 {
        if let Some(st) = &status {
            data = st.pool_take_by_id(conn_id);
        }
        if data.is_none() {
            tracing::warn!(
                "OpenStream 携带 conn_id={conn_id} 但 agent 预连接池为空，回退拨号"
            );
        }
    }
    let mut data = match data {
        Some(s) => s,
        None => match tokio::net::TcpStream::connect(data_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("连接网关数据面 {data_addr} 失败: {e}");
                return;
            }
        },
    };
    if write_message(
        &mut data,
        &Message::StreamConn {
            stream_id,
            conn_id,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let mut local = match tokio::net::TcpStream::connect((target.target_host.as_str(), target.target_port))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "连接内网服务 {}:{} 失败: {e}",
                target.target_host,
                target.target_port
            );
            return;
        }
    };
    let _ = tokio::io::copy_bidirectional(&mut data, &mut local).await;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 常驻运行：会话断开后按指数退避重连。`status` 供本地管理页读取。
pub async fn run_agent_with_status(
    cfg: AgentConfig,
    status: Option<Arc<runtime::RuntimeStatus>>,
) -> anyhow::Result<()> {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    loop {
        match run_agent_session_with_status(cfg.clone(), status.clone()).await {
            Ok(()) => tracing::info!("会话正常结束，准备重连"),
            Err(e) => tracing::warn!("会话结束: {e:#}"),
        }
        let wait = backoff.next_delay();
        tracing::info!("{wait:?} 后重连");
        tokio::time::sleep(wait).await;
    }
}

/// 兼容入口：不收集运行时状态的常驻运行。
pub async fn run_agent(cfg: AgentConfig) -> anyhow::Result<()> {
    run_agent_with_status(cfg, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_spec() {
        let cfg = parse_tunnel_spec("web:7200:127.0.0.1:8080").unwrap();
        assert_eq!(cfg.tunnel_id, "web");
        assert_eq!(cfg.listen_port, 7200);
        assert_eq!(cfg.target_host, "127.0.0.1");
        assert_eq!(cfg.target_port, 8080);
    }

    #[test]
    fn parse_spec_with_auto_port() {
        let cfg = parse_tunnel_spec("ssh:0:localhost:22").unwrap();
        assert_eq!(cfg.listen_port, 0, "0 表示由网关自动分配");
        assert_eq!(cfg.target_port, 22);
    }

    #[test]
    fn parse_rejects_wrong_part_count() {
        assert_eq!(
            parse_tunnel_spec("web:7200:127.0.0.1").unwrap_err(),
            SpecError::BadFormat("web:7200:127.0.0.1".into())
        );
        assert!(matches!(
            parse_tunnel_spec("a:1:b:2:3"),
            Err(SpecError::BadFormat(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_ports() {
        assert_eq!(
            parse_tunnel_spec("web:abc:127.0.0.1:8080").unwrap_err(),
            SpecError::BadPort("abc".into())
        );
        assert_eq!(
            parse_tunnel_spec("web:7200:127.0.0.1:99999").unwrap_err(),
            SpecError::BadPort("99999".into())
        );
    }

    #[test]
    fn parse_rejects_empty_name_or_host() {
        assert_eq!(
            parse_tunnel_spec(":7200:127.0.0.1:8080").unwrap_err(),
            SpecError::EmptyName
        );
        assert!(matches!(
            parse_tunnel_spec("web:7200::8080"),
            Err(SpecError::BadFormat(_))
        ));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(8), "封顶后不再增长");
    }

    #[test]
    fn backoff_reset_returns_to_base() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
        b.next_delay();
        b.next_delay();
        b.reset(Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
