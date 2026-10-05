//! fap-gateway：网关命令行入口。

use std::collections::HashMap;
use std::time::Duration;

use clap::Parser;
use fap_gateway::{Gateway, GatewayConfig};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fap-gateway", version, about = "fap 内网穿透网关（服务端）")]
struct Cli {
    /// TOML 配置文件路径；提供时覆盖大部分命令行默认值
    #[arg(long)]
    config: Option<String>,

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

/// 把 TOML 配置转换为运行时 GatewayConfig。
fn toml_to_config(t: fap_protocol::config::GatewayToml) -> anyhow::Result<GatewayConfig> {
    t.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut auth_hmac = HashMap::new();
    for (dev, hex) in t.auth_hmac {
        let key = fap_protocol::config::decode_hmac_hex(&hex)
            .map_err(|e| anyhow::anyhow!("auth_hmac[{dev}]: {e}"))?;
        auth_hmac.insert(dev, key);
    }
    Ok(GatewayConfig {
        control_addr: t.control_addr.parse()?,
        data_addr: t.data_addr.parse()?,
        shared_addr: t.shared_addr.map(|s| s.parse()).transpose()?,
        admin_addr: t.admin_addr.map(|s| s.parse()).transpose()?,
        admin_token: t.admin_token,
        store_file: t.store_file.map(std::path::PathBuf::from),
        console_backend: t.console_backend.map(|s| s.parse()).transpose()?,
        console_host: t.console_host,
        auth: t.auth,
        auth_hmac,
        heartbeat_timeout: Duration::from_secs(t.heartbeat_timeout_secs),
        stream_setup_timeout: Duration::from_secs(t.stream_setup_timeout_secs),
    })
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // 1. TOML 配置优先；2. 命令行补充/覆盖
    let mut auth = HashMap::new();
    for entry in &cli.auth {
        let (device, token) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("--auth 格式应为 DEVICE:TOKEN，实际: {entry}"))?;
        auth.insert(device.to_string(), token.to_string());
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let cfg: GatewayConfig = if let Some(path) = &cli.config {
            let src = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("读取配置 {path} 失败: {e}"))?;
            let mut t = fap_protocol::config::GatewayToml::from_toml_str(&src)
                .map_err(|e| anyhow::anyhow!("解析配置 {path} 失败: {e}"))?;
            // 命令行 --auth 追加到 TOML 的 auth 表
            for (d, tk) in auth {
                t.auth.entry(d).or_insert(tk);
            }
            toml_to_config(t)?
        } else {
            if auth.is_empty() {
                anyhow::bail!("至少需要一个 --auth DEVICE:TOKEN 或 --config gateway.toml");
            }
            GatewayConfig {
                control_addr: cli.control_addr.parse()?,
                data_addr: cli.data_addr.parse()?,
                auth,
                heartbeat_timeout: Duration::from_secs(cli.heartbeat_timeout_secs),
                stream_setup_timeout: Duration::from_secs(cli.stream_setup_timeout_secs),
                ..Default::default()
            }
        };
        let gateway = Gateway::start(cfg).await?;
        tokio::signal::ctrl_c().await?;
        tracing::info!("收到 Ctrl+C，网关退出");
        gateway.shutdown().await;
        Ok::<(), anyhow::Error>(())
    })
}
