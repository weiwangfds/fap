//! fap-access 核心：本地监听 → 每连接经共享单端口接入指定隧道。

use std::time::Duration;

use fap_protocol::{write_message, Message};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

/// 访问器配置。
#[derive(Debug, Clone)]
pub struct AccessConfig {
    /// 网关共享端口地址（host:port）。
    pub server_addr: String,
    /// 要接入的隧道名。
    pub tunnel_id: String,
    /// 隧道访问令牌。
    pub token: String,
    /// 本地监听地址。
    pub listen_addr: String,
    /// 握手超时。
    pub connect_timeout: Duration,
}

/// 启动本地转发：每条到 listen_addr 的连接都会经共享端口接入隧道。
/// 绑定成功后立即返回监听地址；accept 循环在后台任务中常驻。
pub async fn run_local_forward(cfg: AccessConfig) -> anyhow::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    let addr = listener.local_addr()?;
    tracing::info!(
        "fap-access 本地监听 {addr} -> 网关 {} 隧道 {}",
        cfg.server_addr,
        cfg.tunnel_id
    );
    let cfg = std::sync::Arc::new(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((local, peer)) = listener.accept().await else { continue };
            let cfg = cfg.clone();
            tokio::spawn(async move {
                tracing::debug!("本地连接 {peer} 接入");
                if let Err(e) = handle_local(local, &cfg).await {
                    tracing::debug!("本地连接 {peer} 结束: {e:#}");
                }
            });
        }
    });
    Ok(addr)
}

/// 单条本地连接：连网关 → AccessRequest → 裸转发。
async fn handle_local(mut local: TcpStream, cfg: &AccessConfig) -> anyhow::Result<()> {
    let connect = tokio::time::timeout(
        cfg.connect_timeout,
        TcpStream::connect(&cfg.server_addr),
    )
    .await;
    let mut remote = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(anyhow::Error::new(e).context("连接网关失败")),
        Err(_) => anyhow::bail!("连接网关超时"),
    };
    write_message(
        &mut remote,
        &Message::AccessRequest {
            tunnel_id: cfg.tunnel_id.clone(),
            token: cfg.token.clone(),
        },
    )
    .await?;
    // 验证网关是否接受：拒绝时网关直接关闭连接；Accept 无显式应答帧，
    // 用「写一条探测数据 + 读」的方式不可靠，这里采用直接转发的策略：
    // 若令牌错误，网关关闭连接 → copy_bidirectional 自然结束。
    let _ = copy_bidirectional(&mut local, &mut remote).await;
    Ok(())
}

/// 单次直连模式（不经本地监听，stdin/stdout 桥接由 CLI 决定）。
pub async fn connect_once(cfg: &AccessConfig) -> anyhow::Result<TcpStream> {
    let mut remote = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&cfg.server_addr)).await??;
    write_message(
        &mut remote,
        &Message::AccessRequest {
            tunnel_id: cfg.tunnel_id.clone(),
            token: cfg.token.clone(),
        },
    )
    .await?;
    Ok(remote)
}
