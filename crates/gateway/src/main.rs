//! fap-gateway：网关命令行入口。

use std::collections::HashMap;
use std::time::Duration;

use clap::Parser;
use fap_gateway::{Gateway, GatewayConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fap-gateway", version, about = "fap 内网穿透网关（服务端）")]
struct Cli {
    /// 控制面监听地址（agent 注册/心跳）
    #[arg(long, default_value = "0.0.0.0:7100")]
    control_addr: String,

    /// 数据面监听地址（agent 回连承载用户流）
    #[arg(long, default_value = "0.0.0.0:7101")]
    data_addr: String,

    /// 设备凭证，格式 DEVICE:TOKEN，可重复多次
    #[arg(long = "auth", value_name = "DEVICE:TOKEN")]
    auth: Vec<String>,

    /// 心跳超时（秒）
    #[arg(long, default_value_t = 30)]
    heartbeat_timeout_secs: u64,

    /// 用户连接等待 agent 建流的超时（秒）
    #[arg(long, default_value_t = 8)]
    stream_setup_timeout_secs: u64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let mut auth = HashMap::new();
    for entry in &cli.auth {
        let (device, token) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("--auth 格式应为 DEVICE:TOKEN，实际: {entry}"))?;
        auth.insert(device.to_string(), token.to_string());
    }
    if auth.is_empty() {
        anyhow::bail!("至少需要一个 --auth DEVICE:TOKEN，否则没有设备能注册");
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let cfg = GatewayConfig {
            control_addr: cli.control_addr.parse()?,
            data_addr: cli.data_addr.parse()?,
            auth,
            heartbeat_timeout: Duration::from_secs(cli.heartbeat_timeout_secs),
            stream_setup_timeout: Duration::from_secs(cli.stream_setup_timeout_secs),
            ..Default::default()
        };
        let gateway = Gateway::start(cfg).await?;
        tokio::signal::ctrl_c().await?;
        tracing::info!("收到 Ctrl+C，网关退出");
        gateway.shutdown().await;
        Ok::<(), anyhow::Error>(())
    })
}
