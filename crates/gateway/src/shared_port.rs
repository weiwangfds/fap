//! 共享单端口：首字节嗅探 → SNI / HTTP / 控制台反代 / 访问器。

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::protocol_http::{parse_request_head, strip_hop_by_hop, write_headers, RequestHead};
use crate::protocol_tls::parse_sni;
use crate::router::RouteTarget;
use crate::server::State;

use fap_protocol::Message;

/// 受理共享端口连接：嗅探首字节后路由。
pub(crate) async fn serve(listener: TcpListener, _addr: SocketAddr, state: State) {
    loop {
        let Ok((mut conn, peer)) = listener.accept().await else { continue };
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(&mut conn, peer, &st).await {
                debug!("shared_port {peer}: {e:#}");
            }
        });
    }
}

async fn handle_conn(conn: &mut TcpStream, peer: SocketAddr, state: &State) -> anyhow::Result<()> {
    // 预读首字节嗅探（最多 1KB 应足够 TLS ClientHello / HTTP 起始行）
    let mut sniff = [0u8; 1024];
    let n = match conn.peek(&mut sniff).await {
        Ok(n) if n > 0 => n,
        Ok(_) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let buf = &sniff[..n];

    if buf[0] == 0x16 {
        // TLS：尝试 SNI 路由；解析后按目标转 bytes
        let target = state.shared.lock().unwrap().router.route_sni(
            &parse_sni(buf).unwrap_or_default(),
        );
        if let Some(target) = target {
            return forward_to_agent(conn, &state, target, &buf[..n]).await;
        }
        return tls_passthrough_no_route(conn).await;
    }

    if is_http_method_start(buf) {
        return route_http(conn, &state, buf).await;
    }

    if buf[0] == 0x00 {
        // 访问器协议：首帧 AccessRequest（帧长度高字节为 0x00）。
        // 注意 peek 不消费 —— 用 read_message_exact 从 socket 精确读帧。
        return handle_access(conn, &state).await;
    }

    // 其它：直接关闭
    debug!("shared_port {peer}: 未知首字节");
    conn.shutdown().await.ok();
    Ok(())
}

/// 访问器：读 AccessRequest 帧 → 验证 token → OpenStream → 裸管道。
async fn handle_access(conn: &mut TcpStream, state: &State) -> anyhow::Result<()> {
    let msg = match fap_protocol::read_message_exact(conn).await {
        Ok(m) => m,
        Err(e) => {
            debug!("shared_port access: 首帧读取失败: {e}");
            conn.shutdown().await.ok();
            return Ok(());
        }
    };
    let Message::AccessRequest { tunnel_id, token } = msg else {
        conn.shutdown().await.ok();
        return Ok(());
    };
    // 路由 + token 验证
    let target = state.shared.lock().unwrap().router.route_access(&tunnel_id, &token);
    let Some(target) = target else {
        debug!("shared_port access: 隧道 {tunnel_id} 令牌无效或未启用访问器");
        conn.shutdown().await.ok();
        return Ok(());
    };
    // 验证通过：连接变成到内网服务的裸管道（不转发 AccessRequest 帧本身）
    relay_via_agent(conn, state, target, None).await
}

fn is_http_method_start(buf: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}

async fn route_http(conn: &mut TcpStream, state: &State, _peek: &[u8]) -> anyhow::Result<()> {
    // 注意：handle_conn 的 peek 只做嗅探、不消费；这里必须自己从 socket
    // 读完整请求头（消费内核缓冲区），否则 copy_bidirectional 会把原始
    // 请求再转发一遍（重复字节 bug）。
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut head_len: Option<usize> = None;
    let mut tmp = [0u8; 4096];
    while buf.len() < 16 * 1024 {
        if let Some(idx) = find_header_end(&buf) {
            head_len = Some(idx + 4); // \r\n\r\n 末尾
            break; // 不 truncate：buf 中 head 之后可能已带上部分 body
        }
        match conn.read(&mut tmp).await {
            Ok(0) => return Ok(()),
            Ok(k) => buf.extend_from_slice(&tmp[..k]),
            Err(e) => return Err(e.into()),
        }
    }
    let Some(head_len) = head_len else {
        conn.shutdown().await.ok();
        return Ok(());
    };
    let head = match parse_request_head(&buf) {
        Ok(Some(h)) => h,
        Ok(None) => {
            conn.shutdown().await.ok();
            return Ok(());
        }
        Err(_) => {
            bad_request(conn).await.ok();
            return Ok(());
        }
    };
    let body_so_far = head_len;

    // 命中控制台
    if let Some(console_host) = state.cfg.console_host.as_deref() {
        if !console_host.is_empty() && host_matches(&head.host, console_host) {
            return reverse_proxy_console(conn, &state, &head, &buf, body_so_far).await;
        }
    }
    // 命中 host/path 路由
    let route = state
        .shared
        .lock()
        .unwrap()
        .router
        .route_http(&head.host, &head.path);
    if let Some(target) = route {
        // 反向代理：把请求（清理 hop-by-hop 后）发给 agent
        return reverse_proxy_to_agent(conn, &state, target, &head, &buf, body_so_far).await;
    }
    not_found(conn).await.ok();
    Ok(())
}

fn host_matches(host: &str, pattern: &str) -> bool {
    host.eq_ignore_ascii_case(pattern)
}

/// 找 `\r\n\r\n` 的位置。
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn reverse_proxy_to_agent(
    conn: &mut TcpStream,
    state: &State,
    target: RouteTarget,
    head: &RequestHead,
    raw_head: &[u8],
    body_so_far: usize,
) -> anyhow::Result<()> {
    // 打开到 agent 数据面的连接并请求 OpenStream
    let stream_id = state.next_stream_id();
    let device_id = target.device_id.clone();
    let tunnel_id = target.tunnel_id.clone();
    state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&device_id, &tunnel_id)
        .open_stream();

    // 取出 control_tx
    let control = {
        let shared = state.shared.lock().unwrap();
        shared.registry.control_tx(&device_id)
    };
    let Some(control) = control else {
        bad_gateway(conn).await.ok();
        return Ok(());
    };

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    {
        let mut shared = state.shared.lock().unwrap();
        shared.matcher.wait(stream_id, ack_tx);
    }
    if control
        .send(fap_protocol::Message::OpenStream {
            stream_id,
            tunnel_id: tunnel_id.clone(),
        })
        .await
        .is_err()
    {
        state.shared.lock().unwrap().matcher.cancel(stream_id);
        bad_gateway(conn).await.ok();
        return Ok(());
    }

    // 等待 agent 数据连接（带超时）
    let agent_data = match tokio::time::timeout(state.cfg.stream_setup_timeout, ack_rx).await {
        Ok(Ok(s)) => s,
        _ => {
            state.shared.lock().unwrap().matcher.cancel(stream_id);
            bad_gateway(conn).await.ok();
            return Ok(());
        }
    };

    // 清理 hop-by-hop
    let cleaned = strip_hop_by_hop(&head.headers);
    // 重写 request-line + 序列化头
    let mut req_bytes: Vec<u8> = Vec::new();
    req_bytes.extend_from_slice(head.method.as_bytes());
    req_bytes.extend_from_slice(b" ");
    req_bytes.extend_from_slice(head.path.as_bytes());
    req_bytes.extend_from_slice(b" HTTP/1.1\r\n");
    // Host 必须保留
    req_bytes.extend_from_slice(b"host: ");
    req_bytes.extend_from_slice(head.host.as_bytes());
    req_bytes.extend_from_slice(b"\r\n");
    req_bytes.extend_from_slice(&write_headers(&cleaned));
    req_bytes.extend_from_slice(b"\r\n"); // 头部结束空行
    // 已读到的 body 片段
    req_bytes.extend_from_slice(&raw_head[body_so_far..]);
    // 根据 Content-Length 读取剩余 body（若指定）；否则不读 body（避免挂起）
    let content_length: usize = cleaned
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let already = raw_head.len() - body_so_far;
    let need = content_length.saturating_sub(already);
    let mut tmp = [0u8; 8192];
    let mut read = 0;
    while read < need {
        match conn.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                req_bytes.extend_from_slice(&tmp[..n]);
                read += n;
            }
            Err(_) => break,
        }
    }

    let mut agent = agent_data;
    if agent.write_all(&req_bytes).await.is_err() {
        return Ok(());
    }
    let _ = tokio::io::copy_bidirectional(conn, &mut agent).await;
    let _ = state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&device_id, &tunnel_id)
        .close_stream();
    Ok(())
}

async fn reverse_proxy_console(
    conn: &mut TcpStream,
    state: &State,
    head: &RequestHead,
    raw_head: &[u8],
    body_so_far: usize,
) -> anyhow::Result<()> {
    let backend = match state.cfg.console_backend {
        Some(b) => b,
        None => {
            not_found(conn).await.ok();
            return Ok(());
        }
    };
    let mut upstream = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(_) => {
            bad_gateway(conn).await.ok();
            return Ok(());
        }
    };
    let cleaned = strip_hop_by_hop(&head.headers);
    let mut req: Vec<u8> = Vec::new();
    req.extend_from_slice(head.method.as_bytes());
    req.extend_from_slice(b" ");
    req.extend_from_slice(head.path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\n");
    req.extend_from_slice(b"host: ");
    req.extend_from_slice(head.host.as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(&write_headers(&cleaned));
    req.extend_from_slice(b"\r\n"); // 头部结束空行
    if upstream.write_all(&req).await.is_err() {
        return Ok(());
    }
    // 反代控制台：不知道后端期望的 body 长度，按 Content-Length 限读
    let upstream_content_length: usize = cleaned
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let already = raw_head.len() - body_so_far;
    let need = upstream_content_length.saturating_sub(already);
    let mut upstream_buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut read = 0;
    while read < need {
        match conn.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                upstream_buf.extend_from_slice(&tmp[..n]);
                read += n;
            }
            Err(_) => break,
        }
    }
    if !upstream_buf.is_empty() {
        upstream.write_all(&upstream_buf).await.ok();
    }
    let _ = tokio::io::copy_bidirectional(conn, &mut upstream).await;
    Ok(())
}

/// 通用中继：OpenStream 到 agent 数据面 → 可选 preface → 双向裸转发。
/// TLS pass-through（preface=peeked ClientHello）与访问器（preface=None）共用。
async fn relay_via_agent(
    conn: &mut TcpStream,
    state: &State,
    target: RouteTarget,
    preface: Option<&[u8]>,
) -> anyhow::Result<()> {
    let stream_id = state.next_stream_id();
    let device_id = target.device_id.clone();
    let tunnel_id = target.tunnel_id.clone();
    state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&device_id, &tunnel_id)
        .open_stream();
    let control = state
        .shared
        .lock()
        .unwrap()
        .registry
        .control_tx(&device_id);
    let Some(control) = control else {
        conn.shutdown().await.ok();
        let _ = state
            .shared
            .lock()
            .unwrap()
            .metrics
            .get_or_create(&device_id, &tunnel_id)
            .close_stream();
        return Ok(());
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.shared.lock().unwrap().matcher.wait(stream_id, tx);
    if control
        .send(fap_protocol::Message::OpenStream {
            stream_id,
            tunnel_id: tunnel_id.clone(),
        })
        .await
        .is_err()
    {
        state.shared.lock().unwrap().matcher.cancel(stream_id);
        let _ = state
            .shared
            .lock()
            .unwrap()
            .metrics
            .get_or_create(&device_id, &tunnel_id)
            .close_stream();
        return Ok(());
    }
    let mut agent = match tokio::time::timeout(state.cfg.stream_setup_timeout, rx).await {
        Ok(Ok(s)) => s,
        _ => {
            state.shared.lock().unwrap().matcher.cancel(stream_id);
            let _ = state
                .shared
                .lock()
                .unwrap()
                .metrics
                .get_or_create(&device_id, &tunnel_id)
                .close_stream();
            return Ok(());
        }
    };
    if let Some(p) = preface {
        if !p.is_empty() {
            agent.write_all(p).await.ok();
        }
    }
    let _ = tokio::io::copy_bidirectional(conn, &mut agent).await;
    let _ = state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&device_id, &tunnel_id)
        .close_stream();
    Ok(())
}

async fn forward_to_agent(
    conn: &mut TcpStream,
    state: &State,
    target: RouteTarget,
    peek: &[u8],
) -> anyhow::Result<()> {
    // TLS pass-through：peek 的 ClientHello 作为 preface，其后字节流式透传。
    relay_via_agent(conn, state, target, Some(peek)).await
}

async fn tls_passthrough_no_route(conn: &mut TcpStream) -> anyhow::Result<()> {
    warn!("shared_port: TLS 但无 SNI 匹配");
    conn.shutdown().await.ok();
    Ok(())
}

async fn bad_request(conn: &mut TcpStream) -> std::io::Result<()> {
    conn.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    conn.shutdown().await
}

async fn bad_gateway(conn: &mut TcpStream) -> std::io::Result<()> {
    conn.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    conn.shutdown().await
}

async fn not_found(conn: &mut TcpStream) -> std::io::Result<()> {
    conn.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    conn.shutdown().await
}

// 测试用：导出无用的引用防止 warning
#[allow(dead_code)]
fn _force_used(_h: &HashMap<String, String>) {}