//! fap-agent：客户端命令行入口。

use std::time::Duration;
use clap::Parser;
use fap_agent::runtime::RuntimeStatus;
use fap_agent::{local_ui, parse_tunnel_spec, run_agent_with_status, AgentConfig};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fap-agent", version, about = "fap 内网穿透客户端（内网侧）")]
struct Cli {
    /// TOML 配置文件路径
    #[arg(long)]
    config: Option<String>,

    /// 网关控制面地址（host:port）
    #[arg(long, default_value = "127.0.0.1:7100")]
    server: String,

    /// 设备 ID（需与网关 --auth 中的登记一致）
    #[arg(long)]
    device_id: Option<String>,

    /// 设备令牌
    #[arg(long)]
    token: Option<String>,

    /// 隧道规格 NAME:PORT:TARGET_HOST:TARGET_PORT，可重复多次。
    /// PORT 填 0 表示由网关自动分配（或走共享单端口）。
    #[arg(long = "tunnel", value_name = "NAME:PORT:TARGET_HOST:TARGET_PORT")]
    tunnels: Vec<String>,

    /// 心跳间隔（秒）
    #[arg(long, default_value_t = 10)]
    heartbeat_interval_secs: u64,

    /// 登录用户名（控制台展示用）
    #[arg(long, default_value = "")]
    user: String,

    /// 本地管理页监听地址（仅回环！例如 127.0.0.1:7800；不传则不启用）
    #[arg(long)]
    local_ui: Option<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let (cfg_server, cfg_device, cfg_token, cfg_user, mut tunnels, hb_secs) =
        if let Some(path) = &cli.config {
            let src = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("读取配置 {path} 失败: {e}"))?;
            let t = fap_protocol::config::AgentToml::from_toml_str(&src)
                .map_err(|e| anyhow::anyhow!("解析配置 {path} 失败: {e}"))?;
            t.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
            (
                t.server_addr,
                t.device_id,
                t.token,
                t.user,
                t.tunnels,
                t.heartbeat_interval_secs,
            )
        } else {
            (
                cli.server.clone(),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                cli.heartbeat_interval_secs,
            )
        };

    let server = if cli.server != "127.0.0.1:7100" || cfg_server.is_empty() {
        cli.server.clone()
    } else {
        cfg_server
    };
    let device_id = cli.device_id.clone().filter(|s| !s.is_empty()).unwrap_or(cfg_device);
    let token = cli.token.clone().filter(|s| !s.is_empty()).unwrap_or(cfg_token);
    let user = if !cli.user.is_empty() { cli.user.clone() } else { cfg_user };

    // 命令行 --tunnel 追加（优先于配置文件）
    for spec in &cli.tunnels {
        tunnels.push(parse_tunnel_spec(spec)?);
    }
    if tunnels.is_empty() {
        anyhow::bail!("至少需要一个 --tunnel 规格或配置文件中的 [[tunnels]]");
    }
    if device_id.is_empty() || token.is_empty() {
        anyhow::bail!("需要 --device-id/--token 或 --config agent.toml");
    }

    let cfg = AgentConfig {
        server_addr: server,
        device_id,
        token,
        user,
        pk: None,
        tunnels,
        heartbeat_interval: Duration::from_secs(hb_secs),
        connect_timeout: Duration::from_secs(5),
    };

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let status = Arc::new(RuntimeStatus::new(
            &cfg.device_id,
            &cfg.server_addr,
        ));
        // 本地管理页（仅回环地址使用）
        if let Some(ui_addr) = cli.local_ui {
            if !ui_addr.starts_with("127.0.0.1") && !ui_addr.starts_with("[::1]") {
                anyhow::bail!("--local-ui 只允许绑定回环地址（当前: {ui_addr}）");
            }
            let addr: std::net::SocketAddr = ui_addr.parse()?;
            let st = status.clone();
            tokio::spawn(async move {
                if let Err(e) = local_ui::serve(st, addr).await {
                    tracing::warn!("本地管理页退出: {e:#}");
                }
            });
        }
        tokio::select! {
            result = run_agent_with_status(cfg, Some(status)) => result?,
            _ = tokio::signal::ctrl_c() => tracing::info!("收到 Ctrl+C，客户端退出"),
        }
        Ok::<(), anyhow::Error>(())
    })
}