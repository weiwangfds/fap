//! agent 本地管理页：rust-embed 内嵌控制台静态导出 + 本机状态 API。
//!
//! - `GET /` 及静态资源 → 内嵌的 apps/console-web/out（M6 构建产物）
//! - `GET /api/local/status` → 本机视角的状态 JSON
//!
//! 仅绑定回环地址使用；agent 是"本机视角"，看不到其它设备。

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde_json::json;

use crate::runtime::RuntimeStatus;

/// M6 构建产物（`next build` 的静态导出目录，相对 agent 的 Cargo.toml）。
/// debug 构建运行时直接读文件系统（可热改前端）；release 构建编译期内嵌。
/// release 前需先在 apps/console-web 执行 `npm run build`。
#[derive(RustEmbed)]
#[folder = "../../apps/console-web/out"]
struct UiAssets;

/// 启动本地管理页伺服（应仅绑定 127.0.0.1）。
pub async fn serve(status: Arc<RuntimeStatus>, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/local/status", get(local_status))
        .fallback(ui_fallback)
        .with_state(status);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("agent 本地管理页: http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn local_status(State(st): State<Arc<RuntimeStatus>>) -> impl IntoResponse {
    let tunnels = st.tunnels_read();
    Json(json!({
        "device_id": st.device_id,
        "registered": st.registered.load(Ordering::Relaxed),
        "server_addr": st.server_addr,
        "active_streams": st.active_streams.load(Ordering::Relaxed),
        "total_streams": st.total_streams.load(Ordering::Relaxed),
        "last_error": st.last_error_snapshot(),
        "tunnels": tunnels,
    }))
}

async fn ui_fallback(uri: Uri) -> impl IntoResponse {
    // 静态导出没有服务端路由；按路径取资产，缺省回 index.html（SPA 由页面自行跳转）
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match UiAssets::get(path).or_else(|| UiAssets::get("index.html")) {
        Some(f) => {
            let mime = mime_for(path);
            ([(http::header::CONTENT_TYPE, mime)], f.data.to_vec()).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "UI 资产缺失：请先在 apps/console-web 运行 npm run build",
        )
            .into_response(),
    }
}

fn mime_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

use axum::http;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeStatus;

    #[tokio::test]
    async fn local_status_reflects_runtime() {
        let st = RuntimeStatus::new("dev-x", "127.0.0.1:7100");
        st.set_registered(true);
        let app = Router::new()
            .route(
                "/api/local/status",
                get(local_status),
            )
            .with_state(Arc::new(st));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let body = reqwest_get(&format!("http://{addr}/api/local/status")).await;
        assert!(body.contains("\"device_id\":\"dev-x\""), "{body}");
        assert!(body.contains("\"registered\":true"), "{body}");
    }

    async fn reqwest_get(url: &str) -> String {
        // 不引新依赖：用 tokio 原生 HTTP/1.0 GET
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = url
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap()
            .to_string();
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        s.write_all(format!("GET /api/local/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}