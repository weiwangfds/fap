//! 网关接线：控制/数据/隧道监听、会话生命周期、流量转发、admin API。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info, warn};

use fap_protocol::{
    hmac, read_message, read_message_exact, write_message, FrameDecoder, ListenerInfo, Message,
    TunnelConfig, HMAC_BYTES,
};

use crate::admin;
use crate::registry::{DeviceRegistry, RegisterError};
use crate::router::TunnelRouter;
use crate::store::TunnelStore;
use crate::streams::StreamMatcher;

/// 网关运行配置。
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// 控制面监听地址（agent 注册/心跳）。
    pub control_addr: SocketAddr,
    /// 数据面监听地址（agent 回连承载用户流）。
    pub data_addr: SocketAddr,
    /// 共享单端口监听地址（HTTP 后缀 / SNI / 访问器，M3/M4）。
    pub shared_addr: Option<SocketAddr>,
    /// admin API 监听地址；None = 不启用。
    pub admin_addr: Option<SocketAddr>,
    /// admin API 的 Bearer 令牌；None = 不校验（仅建议本机回环使用）。
    pub admin_token: Option<String>,
    /// 控制台配置落盘文件；None = 不持久化。
    pub store_file: Option<PathBuf>,
    /// 控制台反代目标（Next.js 控制台进程地址），按 Host/SNI 匹配 console_host。
    pub console_backend: Option<SocketAddr>,
    /// 共享端口上识别为控制台的域名。
    pub console_host: Option<String>,
    /// 明文 token 表：device_id -> token（M2 兼容）。
    pub auth: HashMap<String, String>,
    /// HMAC-SHA256 共享密钥表：device_id -> 32 字节密钥（M2.5c）。
    /// 若设备同时出现在两表里，HMAC 优先。
    pub auth_hmac: HashMap<String, [u8; HMAC_BYTES]>,
    /// 心跳超时，超时设备被清理；0 表示不清理。
    pub heartbeat_timeout: Duration,
    /// 用户连接等待 agent 建流的超时。
    pub stream_setup_timeout: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            control_addr: "0.0.0.0:7100".parse().unwrap(),
            data_addr: "0.0.0.0:7101".parse().unwrap(),
            shared_addr: None,
            admin_addr: None,
            admin_token: None,
            store_file: None,
            console_backend: None,
            console_host: None,
            auth: HashMap::new(),
            auth_hmac: HashMap::new(),
            heartbeat_timeout: Duration::from_secs(30),
            stream_setup_timeout: Duration::from_secs(8),
        }
    }
}

/// 锁保护的核心状态。约定：锁内不得 await（store 的文件 IO 例外，耗时可控）。
pub(crate) struct Shared {
    pub(crate) registry: DeviceRegistry,
    pub(crate) router: TunnelRouter,
    matcher: StreamMatcher<TcpStream>,
    pub(crate) store: TunnelStore,
    /// 各设备当前实际生效的隧道全集（注册与控制台下发都会更新）。
    pub(crate) runtime: HashMap<String, Vec<TunnelConfig>>,
    /// 每隧道运行时指标（bytes_tx/rx/active/total）。
    pub(crate) metrics: crate::metrics::MetricsRegistry,
}

#[derive(Clone)]
pub(crate) struct State {
    pub(crate) shared: Arc<Mutex<Shared>>,
    seq: Arc<AtomicU64>,
    /// 配置修订号（ConfigPush 用）。
    pub(crate) revision: Arc<AtomicU64>,
    /// 唤醒隧道监听任务重新检查端口归属（端口被释放时自行退出）。
    pub(crate) wake: broadcast::Sender<u16>,
    pub(crate) cfg: Arc<GatewayConfig>,
    data_port: u16,
    /// 隧道监听与控制面同 IP 绑定。
    pub(crate) bind_ip: std::net::IpAddr,
}

impl State {
    pub(crate) fn data_port(&self) -> u16 {
        self.data_port
    }
    pub(crate) fn next_stream_id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

/// 运行中的网关实例。
pub struct Gateway {
    /// 控制面实际监听地址（端口可为 0 自动分配后的真实值）。
    pub control_addr: SocketAddr,
    /// 数据面实际监听地址。
    pub data_addr: SocketAddr,
    /// 共享单端口实际监听地址。
    pub shared_addr: Option<SocketAddr>,
    /// admin API 实际监听地址。
    pub admin_addr: Option<SocketAddr>,
    state: State,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gateway {
    /// 启动网关：绑定控制/数据/共享/admin 监听并开始受理 agent 注册。
    pub async fn start(cfg: GatewayConfig) -> anyhow::Result<Self> {
        let control = TcpListener::bind(cfg.control_addr).await?;
        let data = TcpListener::bind(cfg.data_addr).await?;
        let control_addr = control.local_addr()?;
        let data_addr = data.local_addr()?;

        // Arc 移入 state 之前先取出后续要用的配置
        let admin_addr_cfg = cfg.admin_addr;
        let admin_token = cfg.admin_token.clone();

        let mut shared_listener = match cfg.shared_addr {
            Some(a) => {
                let l = TcpListener::bind(a).await?;
                let addr = l.local_addr()?;
                Some((l, addr))
            }
            None => None,
        };
        let shared_listen_addr = shared_listener.as_ref().map(|(_, a)| *a);

        let (wake, _) = broadcast::channel::<u16>(64);
        let state = State {
            shared: Arc::new(Mutex::new(Shared {
                registry: DeviceRegistry::new(cfg.auth.clone()),
                router: TunnelRouter::default(),
                matcher: StreamMatcher::new(),
                store: TunnelStore::new(cfg.store_file.clone())?,
                runtime: HashMap::new(),
                metrics: crate::metrics::MetricsRegistry::default(),
            })),
            seq: Arc::new(AtomicU64::new(1)),
            revision: Arc::new(AtomicU64::new(1)),
            wake,
            cfg: Arc::new(cfg),
            data_port: data_addr.port(),
            bind_ip: control_addr.ip(),
        };

        let mut tasks = Vec::new();
        {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = control_accept_loop(control, st).await {
                    warn!("控制面退出: {e:#}");
                }
            }));
        }
        {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = data_accept_loop(data, st).await {
                    warn!("数据面退出: {e:#}");
                }
            }));
        }
        if let Some((listener, addr)) = shared_listener.take() {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                crate::shared_port::serve(listener, addr, st).await;
            }));
        }
        if state.cfg.heartbeat_timeout > Duration::ZERO {
            let st = state.clone();
            tasks.push(tokio::spawn(async move { sweep_loop(st).await }));
        }

        let admin_addr = match admin_addr_cfg {
            Some(a) => {
                let listener = tokio::net::TcpListener::bind(a).await?;
                let addr = listener.local_addr()?;
                let st = state.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = admin::serve(listener, st, admin_token).await {
                        warn!("admin API 退出: {e:#}");
                    }
                }));
                Some(addr)
            }
            None => None,
        };

        info!(
            "fap 网关启动: 控制 {control_addr} / 数据 {data_addr} / admin {:?}",
            admin_addr
        );
        Ok(Gateway {
            control_addr,
            data_addr,
            shared_addr: shared_listen_addr,
            admin_addr,
            state,
            tasks,
        })
    }

    /// 查询某设备某条隧道当前实际监听的端口（含自动分配的端口）。
    pub fn tunnel_port(&self, device_id: &str, tunnel_id: &str) -> Option<u16> {
        self.state
            .shared
            .lock()
            .unwrap()
            .router
            .tunnel_port(device_id, tunnel_id)
    }

    /// admin API 实际监听地址（未启用则 None）。
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        self.admin_addr
    }

    /// 设备是否在线。
    pub fn is_online(&self, device_id: &str) -> bool {
        self.state.shared.lock().unwrap().registry.is_online(device_id)
    }

    /// 设备元信息。
    pub fn device_info(&self, device_id: &str) -> Option<fap_protocol::DeviceInfo> {
        self.state.shared.lock().unwrap().registry.device_info(device_id)
    }

    /// 某隧道的实时指标快照。
    pub fn metrics(
        &self,
        device_id: &str,
        tunnel_id: &str,
    ) -> Option<crate::metrics::MetricsSnapshot> {
        self.state
            .shared
            .lock()
            .unwrap()
            .metrics
            .snapshot(device_id, tunnel_id)
    }

    /// 停止网关主任务。
    ///
    /// 已知简化：每条隧道的监听任务未逐一跟踪，进程退出时随运行时回收。
    pub async fn shutdown(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

async fn control_accept_loop(listener: TcpListener, state: State) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("控制连接来自 {peer}");
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control(stream, st).await {
                debug!("控制会话结束（{peer}）: {e:#}");
            }
        });
    }
}

async fn handle_control(stream: TcpStream, state: State) -> anyhow::Result<()> {
    let (mut rh, mut wh2) = stream.into_split();
    let mut dec = FrameDecoder::new();
    let mut hmac_already_passed = false;

    let first = read_message(&mut rh, &mut dec).await?;
    let Message::Register {
        device_id,
        token,
        device_info,
        pk: _,
        tunnels: declared,
    } = first
    else {
        anyhow::bail!("首条消息必须是 Register");
    };

    // HMAC 优先：若设备在 auth_hmac 表里，走 challenge-response。
    if state.cfg.auth_hmac.contains_key(&device_id) {
        let secret = state.cfg.auth_hmac[&device_id];
        let mut nonce = [0u8; HMAC_BYTES];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(0x5a);
        }
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        write_message(&mut wh2, &Message::AuthChallenge { nonce, ts_ms }).await?;
        let resp = read_message(&mut rh, &mut dec).await?;
        let Message::AuthChallengeResp { sig, ts_ms: resp_ts } = resp else {
            write_message(
                &mut wh2,
                &Message::RegisterAck {
                    ok: false,
                    error: Some("HMAC 模式期望 AuthChallengeResp".into()),
                    data_port: 0,
                    listeners: vec![],
                    applied_tunnels: vec![],
                },
            )
            .await?;
            anyhow::bail!("HMAC 模式收到非预期响应");
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let skew = if resp_ts > now { resp_ts - now } else { now - resp_ts };
        if skew > 120_000 {
            write_message(
                &mut wh2,
                &Message::RegisterAck {
                    ok: false,
                    error: Some("HMAC 挑战 ts 过期（>120s 偏差）".into()),
                    data_port: 0,
                    listeners: vec![],
                    applied_tunnels: vec![],
                },
            )
            .await?;
            anyhow::bail!("HMAC ts 偏差过大: {skew}ms");
        }
        let expected = hmac::compute(&secret, &nonce, resp_ts);
        if !hmac::constant_time_eq(&sig, &expected) {
            write_message(
                &mut wh2,
                &Message::RegisterAck {
                    ok: false,
                    error: Some("HMAC 签名验证失败".into()),
                    data_port: 0,
                    listeners: vec![],
                    applied_tunnels: vec![],
                },
            )
            .await?;
            anyhow::bail!("HMAC 签名错误");
        }
        // HMAC 已通过：使用占位 token 进入注册流程
        let placeholder = format!("hmac:{}", device_id);
        let token = placeholder;
        // HMAC 已验证：标记 authenticated=true 跳过 legacy token 比对
        hmac_already_passed = true;
        // fall-through to 通用注册流程（HMAC 已被 gateway 接受）
    }

    // 1. 认证并登记会话
    let (control_tx, control_rx) = mpsc::channel::<Message>(64);
    let session_tx = control_tx.clone();
    let authenticated = !state.cfg.auth_hmac.contains_key(&device_id)
        || hmac_already_passed;
    let reg = state.shared.lock().unwrap().registry.register(
        &device_id,
        &token,
        control_tx,
        device_info,
        Instant::now(),
        authenticated,
    );
    let _replaced = match reg {
        Ok(r) => r,
        Err(RegisterError::BadToken) => {
            write_message(
                &mut wh2,
                &Message::RegisterAck {
                    ok: false,
                    error: Some("认证失败：设备或令牌错误".into()),
                    data_port: 0,
                    listeners: vec![],
                    applied_tunnels: vec![],
                },
            )
            .await?;
            anyhow::bail!("设备 {device_id} 认证失败");
        }
    };

    // 2. 生效配置：控制台覆盖优先
    let effective = state
        .shared
        .lock()
        .unwrap()
        .store
        .effective(&device_id, declared);

    // 3. 应用隧道（移除旧 → 绑定新 → 登记路由）
    let bound = match apply_tunnels(&state, &device_id, &effective).await {
        Ok(b) => b,
        Err(e) => {
            state.shared.lock().unwrap().registry.force_remove(&device_id);
            write_message(
                &mut wh2,
                &Message::RegisterAck {
                    ok: false,
                    error: Some(format!("{e:#}")),
                    data_port: 0,
                    listeners: vec![],
                    applied_tunnels: vec![],
                },
            )
            .await?;
            anyhow::bail!("设备 {device_id} 隧道绑定失败: {e:#}");
        }
    };

    // 4. 应答（带生效配置全集与实际端口）
    write_message(
        &mut wh2,
        &Message::RegisterAck {
            ok: true,
            error: None,
            data_port: state.data_port,
            listeners: bound
                .iter()
                .map(|(tid, p)| ListenerInfo {
                    tunnel_id: tid.clone(),
                    listen_port: *p,
                })
                .collect(),
            applied_tunnels: effective.clone(),
        },
    )
    .await?;
    info!("设备 {device_id} 注册成功，隧道: {bound:?}");

    // 5. 下行任务：注册表中的 control_tx → 控制连接
    let mut rx = control_rx;
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_message(&mut wh2, &msg).await.is_err() {
                break;
            }
        }
    });

    // 6. 读循环：心跳 / 配置应答
    let read_result: anyhow::Result<()> = loop {
        match read_message(&mut rh, &mut dec).await {
            Ok(Message::Heartbeat { timestamp_ms }) => {
                let _ = state
                    .shared
                    .lock()
                    .unwrap()
                    .registry
                    .heartbeat(&device_id, Instant::now());
                let _ = session_tx.try_send(Message::HeartbeatAck { timestamp_ms });
            }
            Ok(Message::ConfigAck { ok, revision, .. }) => {
                debug!("设备 {device_id} 配置应用应答 ok={ok} rev={revision}");
            }
            Ok(_) => {}
            Err(e) => break Err(anyhow::Error::new(e).context("控制连接读取失败")),
        }
    };

    // 7. 清理：仅当本会话仍是注册者（防止被顶替的旧连接误删新会话）
    {
        let mut shared = state.shared.lock().unwrap();
        if shared.registry.owns(&device_id, &session_tx) {
            shared.registry.force_remove(&device_id);
            let freed = shared.router.remove_device(&device_id);
            drop(shared);
            for p in freed {
                let _ = state.wake.send(p);
            }
        }
    }
    writer.abort();
    read_result
}

/// 注册流程与控制台下发改动共用此入口。
pub(crate) async fn apply_tunnels(
    state: &State,
    device_id: &str,
    tunnels: &[TunnelConfig],
) -> anyhow::Result<Vec<(String, u16)>> {
    let freed = state.shared.lock().unwrap().router.remove_device(device_id);
    if !freed.is_empty() {
        for p in freed {
            let _ = state.wake.send(p);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let bound = bind_tunnels(state, tunnels).await?;
    {
        let mut shared = state.shared.lock().unwrap();
        shared.router.register_bound(device_id, &bound)?;
        shared
            .runtime
            .insert(device_id.to_string(), tunnels.to_vec());
    }
    Ok(bound)
}

async fn bind_tunnels(
    state: &State,
    tunnels: &[TunnelConfig],
) -> anyhow::Result<Vec<(String, u16)>> {
    let mut bound = Vec::new();
    for t in tunnels {
        let addr = SocketAddr::new(state.bind_ip, t.listen_port);
        let listener = bind_with_retry(addr).await?;
        let port = listener.local_addr()?.port();
        let st = state.clone();
        tokio::spawn(async move {
            tunnel_accept_loop(listener, port, st).await;
        });
        bound.push((t.tunnel_id.clone(), port));
    }
    Ok(bound)
}

/// 绑定端口；AddrInUse 时短暂重试（同设备重绑时旧监听释放有延迟）。
async fn bind_with_retry(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let mut delay = Duration::from_millis(50);
    for _ in 0..20 {
        match TcpListener::bind(addr).await {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay * 2, Duration::from_millis(500));
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("绑定 {addr} 失败：端口被占用且重试超时")
}

async fn tunnel_accept_loop(listener: TcpListener, port: u16, state: State) {
    let mut wake_rx = state.wake.subscribe();
    loop {
        tokio::select! {
            _ = wake_rx.recv() => {
                if state.shared.lock().unwrap().router.route(port).is_none() {
                    debug!("隧道监听 {port} 已下线");
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((user, peer)) => {
                        debug!("用户连接 {peer} -> 端口 {port}");
                        let st = state.clone();
                        tokio::spawn(async move {
                            handle_user(user, port, st).await;
                        });
                    }
                    Err(e) => {
                        warn!("端口 {port} accept 失败: {e}");
                        break;
                    }
                }
            }
        }
    }
}

pub(crate) async fn handle_user(mut user: TcpStream, port: u16, state: State) {
    let Some(target) = state.shared.lock().unwrap().router.route(port) else {
        return;
    };
    let Some(control) = state
        .shared
        .lock()
        .unwrap()
        .registry
        .control_tx(&target.device_id)
    else {
        return;
    };

    let stream_id = state.seq.fetch_add(1, Ordering::Relaxed);
    // 指标：open_stream（无论转发成功失败，结束时都需 close）
    state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&target.device_id, &target.tunnel_id)
        .open_stream();
    open_stream_to_device(&state, &control, &target, stream_id, user).await;
    // 收尾：close_stream（无论成功/失败/超时都计数归零）
    state
        .shared
        .lock()
        .unwrap()
        .metrics
        .get_or_create(&target.device_id, &target.tunnel_id)
        .close_stream();
}

/// 通用开流：请求 agent 建数据连接，等待配对后双向转发（带字节计数）。
/// 返回 Some(()) 表示完成了一次转发（无论字节数多少）。
pub(crate) async fn open_stream_to_device(
    state: &State,
    control: &mpsc::Sender<Message>,
    target: &crate::router::RouteTarget,
    stream_id: u64,
    user: TcpStream,
) -> Option<()> {
    let mut user = user;
    let (tx, rx) = oneshot::channel();
    state.shared.lock().unwrap().matcher.wait(stream_id, tx);

    if control
        .send(Message::OpenStream {
            stream_id,
            tunnel_id: target.tunnel_id.clone(),
        })
        .await
        .is_err()
    {
        state.shared.lock().unwrap().matcher.cancel(stream_id);
        return None;
    }

    match tokio::time::timeout(state.cfg.stream_setup_timeout, rx).await {
        Ok(Ok(mut agent_stream)) => {
            // 取出 TunnelMetrics 引用（与 Shared.metrics 中的对象相同）；
            // 锁不必持续持有 — AtomicU64/Mutex 自身 Sync，足以支撑并发计数。
            let metrics = state
                .shared
                .lock()
                .unwrap()
                .metrics
                .get_or_create(&target.device_id, &target.tunnel_id) as *const _;
            // SAFETY: TunnelMetrics 内部全是 AtomicU64/Sync Mutex；并发只读是安全的，
            // 关闭流时由 handle_user 关闭计数与设备清理保证生命周期。
            let metrics: &crate::metrics::TunnelMetrics = unsafe { &*metrics };
            let _ = copy_bidirectional_counted(&mut user, &mut agent_stream, metrics).await;
            Some(())
        }
        _ => {
            state.shared.lock().unwrap().matcher.cancel(stream_id);
            debug!("流 {stream_id} 建立超时或对端放弃");
            None
        }
    }
}

/// 双向转发，期间按字节累加到 metrics。
/// 返回 (tx_bytes, rx_bytes)。
async fn copy_bidirectional_counted(
    a: &mut TcpStream,
    b: &mut TcpStream,
    metrics: &crate::metrics::TunnelMetrics,
) -> std::io::Result<(u64, u64)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];
    let mut tx = 0u64;
    let mut rx = 0u64;
    let mut a_done = false;
    let mut b_done = false;
    while !(a_done && b_done) {
        tokio::select! {
            r = ar.read(&mut buf_a), if !a_done => match r {
                Ok(0) => {
                    // 半关闭：用户侧关闭，通知内网侧 EOF
                    a_done = true;
                    let _ = bw.shutdown().await;
                }
                Ok(n) => { rx += n as u64; metrics.add_rx(n as u64); if bw.write_all(&buf_a[..n]).await.is_err() { b_done = true; a_done = true; } }
                Err(_) => { a_done = true; b_done = true; }
            },
            r = br.read(&mut buf_b), if !b_done => match r {
                Ok(0) => {
                    b_done = true;
                    let _ = aw.shutdown().await;
                }
                Ok(n) => { tx += n as u64; metrics.add_tx(n as u64); if aw.write_all(&buf_b[..n]).await.is_err() { a_done = true; b_done = true; } }
                Err(_) => { a_done = true; b_done = true; }
            },
        }
    }
    Ok((tx, rx))
}

async fn data_accept_loop(listener: TcpListener, state: State) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            let mut s = stream;
            match read_message_exact(&mut s).await {
                Ok(Message::StreamConn { stream_id }) => {
                    if !st.shared.lock().unwrap().matcher.complete(stream_id, s) {
                        debug!("数据连接 {peer} 的流 {stream_id} 无等待者，关闭");
                    }
                }
                other => {
                    debug!("数据连接 {peer} 首帧异常: {other:?}");
                }
            }
        });
    }
}

async fn sweep_loop(state: State) {
    let timeout = state.cfg.heartbeat_timeout;
    let every = std::cmp::max(timeout / 2, Duration::from_secs(1));
    let mut tk = tokio::time::interval(every);
    tk.tick().await; // interval 的首拍立即触发，消耗掉
    loop {
        tk.tick().await;
        let removed = state.shared.lock().unwrap().registry.sweep(timeout, Instant::now());
        for id in removed {
            let freed = state.shared.lock().unwrap().router.remove_device(&id);
            for p in freed {
                let _ = state.wake.send(p);
            }
            warn!("设备 {id} 心跳超时，已下线");
        }
    }
}
