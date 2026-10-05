//! fap-access：命令行入口。
//!
//! 用法（本地转发模式，最常用）：
//!   fap-access --listen 127.0.0.1:2222 --server gw.example.com:443 \
//!              --tunnel ssh --token tok-1
//! 之后 `ssh 127.0.0.1 -p 2222` 即到达内网 SSH。

use clap::Parser;
use fap_access::{run_local_forward, AccessConfig};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "fap-access", version, about = "fap 访问器：按隧道名+令牌接入共享单端口")]
struct Cli {
    /// 本地监听地址
    #[arg(long, default_value = "127.0.0.1:2222")]
    listen: String,

    /// 网关共享端口地址（host:port）
    #[arg(long)]
    server: String,

    /// 隧道名
    #[arg(long)]
    tunnel: String,

    /// 隧道访问令牌
    #[arg(long)]
    token: String,

    /// 握手超时（秒）
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = AccessConfig {
        server_addr: cli.server,
        tunnel_id: cli.tunnel,
        token: cli.token,
        listen_addr: cli.listen,
        connect_timeout: Duration::from_secs(cli.timeout_secs),
    };

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        tokio::select! {
            r = run_local_forward(cfg) => r.map(|_| ()),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到 Ctrl+C，访问器退出");
                Ok(())
            }
        }
    })
}