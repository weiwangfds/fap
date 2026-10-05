//! admin API：控制台后端（axum）。
//!
//! 路由（Bearer 令牌保护）：
//! - `GET  /api/health`                 健康检查
//! - `GET  /api/devices`                设备列表（在线状态 + 生效隧道）
//! - `GET  /api/devices/{dev}/tunnels`  读取控制台配置
//! - `PUT  /api/devices/{dev}/tunnels`  覆盖配置并实时下发（设备在线则立即生效）

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tracing::warn;

use fap_protocol::{Message, TunnelConfig};

use crate::server::State as GatewayState;

pub(crate) struct AdminState {
    state: GatewayState,
    token: Option<String>,
}

pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    state: GatewayState,
    token: Option<String>,
) -> anyhow::Result<()> {
    let st = Arc::new(AdminState { state, token });
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/devices", get(devices))
        .route(
            "/api/devices/{device}/tunnels",
            get(get_tunnels).put(put_tunnels),
        )
        .layer(middleware::from_fn_with_state(st.clone(), auth))
        .with_state(st);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth(
    State(st): State<Arc<AdminState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    if let Some(expected) = &st.token {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }
    next.run(req).await
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

async fn devices(State(st): State<Arc<AdminState>>) -> impl IntoResponse {
    let shared = st.state.shared.lock().unwrap();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.extend(shared.registry.device_ids());
    ids.extend(shared.store.devices());
    ids.extend(shared.runtime.keys().cloned());

    let list: Vec<_> = ids
        .into_iter()
        .map(|id| {
            json!({
                "device_id": id,
                "online": shared.registry.is_online(&id),
                "tunnels": shared.runtime.get(&id).cloned().unwrap_or_default(),
            })
        })
        .collect();
    Json(json!({"devices": list}))
}

async fn get_tunnels(
    State(st): State<Arc<AdminState>>,
    Path(device): Path<String>,
) -> impl IntoResponse {
    let shared = st.state.shared.lock().unwrap();
    match shared.store.get(&device) {
        Some(t) => (StatusCode::OK, Json(json!({"tunnels": t}))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "该设备没有控制台配置"})),
        )
            .into_response(),
    }
}

async fn put_tunnels(
    State(st): State<Arc<AdminState>>,
    Path(device): Path<String>,
    Json(tunnels): Json<Vec<TunnelConfig>>,
) -> axum::response::Response {
    eprintln!("[gw] put_tunnels {device} n={} entry", tunnels.len());
    if let Err(e) = validate(&tunnels) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // 1. 落盘（控制台是事实源）
    let set_result = st
        .state
        .shared
        .lock()
        .unwrap()
        .store
        .set(&device, tunnels.clone());
    let online = st.state.shared.lock().unwrap().registry.is_online(&device);
    eprintln!("[gw] stored, online={online}");

    // 2. 设备在线则立即生效并下发（注意：锁不可跨 await 持有）
    let applied = if online {
        match crate::server::apply_tunnels(&st.state, &device, &tunnels).await {
            Ok(bound) => {
                let revision = st.state.revision.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let control = st.state.shared.lock().unwrap().registry.control_tx(&device);
                if let Some(control) = control {
                    let _ = control
                        .send(Message::ConfigPush {
                            revision,
                            tunnels: tunnels.clone(),
                        })
                        .await;
                }
                st.state
                    .shared
                    .lock()
                    .unwrap()
                    .runtime
                    .insert(device.clone(), tunnels.clone());
                info_applied(&device, &bound);
                true
            }
            Err(e) => {
                warn!("设备 {device} 应用隧道失败: {e:#}");
                false
            }
        }
    } else {
        false
    };

    let ok = set_result.is_ok();
    (
        StatusCode::OK,
        Json(json!({"ok": ok, "device_id": device, "applied": applied})),
    )
        .into_response()
}

fn validate(tunnels: &[TunnelConfig]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for t in tunnels {
        if t.tunnel_id.is_empty() {
            return Err("tunnel_id 不能为空".into());
        }
        if !seen.insert(t.tunnel_id.clone()) {
            return Err(format!("tunnel_id 重复: {}", t.tunnel_id));
        }
        if t.target_host.is_empty() || t.target_port == 0 {
            return Err(format!("隧道 {} 的内网目标无效", t.tunnel_id));
        }
    }
    Ok(())
}

fn info_applied(device: &str, bound: &[(String, u16)]) {
    tracing::info!("设备 {device} 隧道已更新: {bound:?}");
}
