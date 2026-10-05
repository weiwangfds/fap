//! fap-agent：客户端命令行入口。

use std::time::Duration;

use clap::Parser;
use fap_agent::{parse_tunnel_spec, run_agent, AgentConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fap-agent", version, about = "fap 内网穿透客户端（内网侧）")]
struct Cli {
    /// 网关控制面地址（host:port）
    #[arg(long, default_value = "127.0.0.1:7100")]
    server: String,

    /// 设备 ID（需与网关 --auth 中的登记一致）
    #[arg(long)]
    device_id: String,

    /// 设备令牌
    #[arg(long)]
    token: String,

    /// 隧道规格 NAME:PORT:TARGET_HOST:TARGET_PORT，可重复多次。
    /// PORT 填 0 表示由网关自动分配。
    #[arg(long = "tunnel", value_name = "NAME:PORT:TARGET_HOST:TARGET_PORT")]
    tunnels: Vec<String>,

    /// 心跳间隔（秒）
    #[arg(long, default_value_t = 10)]
    heartbeat_interval_secs: u64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if cli.tunnels.is_empty() {
        anyhow::bail!("至少需要一个 --tunnel NAME:PORT:TARGET_HOST:TARGET_PORT");
    }

    let mut tunnels = Vec::new();
    for spec in &cli.tunnels {
        tunnels.push(parse_tunnel_spec(spec)?);
    }

    let cfg = AgentConfig {
        server_addr: cli.server,
        device_id: cli.device_id,
        token: cli.token,
        tunnels,
        heartbeat_interval: Duration::from_secs(cli.heartbeat_interval_secs),
        connect_timeout: Duration::from_secs(5),
    };

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        tokio::select! {
            result = run_agent(cfg) => result?,
            _ = tokio::signal::ctrl_c() => tracing::info!("收到 Ctrl+C，客户端退出"),
        }
        Ok::<(), anyhow::Error>(())
    })
}
