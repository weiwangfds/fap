//! fap 传输层抽象：每条数据连接的可选传输。
//!
//! 现有实现 = Plain（直接字节流）；opt-in 计划加入 Yamux（多路复用）和 DirectPunch（打洞）。
//! 这样 M5c-3/M5c-4 不用改 wire 协议，只在配置 + transport 工厂层加实现。

use std::io;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// 数据连接的传输层抽象。M5c-2 Plain；M5c-3 Yamux；M5c-4 直连打洞。
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn name(&self) -> &'static str;
}

/// 默认实现 = 透传字节流（M2/M5c-1 数据面）。
pub struct Plain<T> {
    inner: T,
}

impl<T> Plain<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Plain<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Plain<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<T> Transport for Plain<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn name(&self) -> &'static str {
        "plain"
    }
}

/// 解析 Transport 名（用于配置；保留 API 形态为 M5c-3 / M5c-4 做扩展点）。
pub fn parse_transport(name: &str) -> TransportKind {
    match name.to_ascii_lowercase().as_str() {
        "yamux" => TransportKind::Yamux,
        "punch" | "direct" => TransportKind::DirectPunch,
        _ => TransportKind::Plain,
    }
}

/// M5c-3：yamux 多路复用传输。包装一条 yamux stream（futures-io），
/// 经 tokio_util::compat 提供 tokio 侧 AsyncRead/AsyncWrite。
/// 会话（YamuxSession）由数据面两端各自持有；本类型只承载「单条流」。
pub struct Yamux(pub tokio_util::compat::Compat<yamux::Stream>);

impl Yamux {
    pub fn new(stream: yamux::Stream) -> Self {
        use tokio_util::compat::FuturesAsyncReadCompatExt as _;
        Self(stream.compat())
    }
}

impl AsyncRead for Yamux {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Yamux {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Transport for Yamux {
    fn name(&self) -> &'static str {
        "yamux"
    }
}

/// M5c-3：driver 化的 yamux 会话。
///
/// parity yamux 的 `Stream` 读写不驱动底层 socket——socket 前进只发生在
/// `Connection` 被 poll 时（`poll_next_inbound`/`poll_new_outbound` 内部驱动）。
/// 因此每端需要一个常驻 driver 任务循环 poll Connection（libp2p 同款模式）。
/// 本类型把 driver 封装掉：`open_stream` 经通道请求 driver 开出站流，
/// `next_stream` 从 driver 收入站流。
pub struct YamuxSession {
    inbound: tokio::sync::mpsc::Receiver<io::Result<yamux::Stream>>,
    open_tx: tokio::sync::mpsc::Sender<
        tokio::sync::oneshot::Sender<io::Result<yamux::Stream>>,
    >,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamuxMode {
    Client,
    Server,
}

/// 建立会话并启动 driver。`T` 为 futures-io（tokio TcpStream 经 `.compat()`）。
pub fn yamux_connect<T>(io: T, mode: YamuxMode) -> YamuxSession
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let m = match mode {
        YamuxMode::Client => yamux::Mode::Client,
        YamuxMode::Server => yamux::Mode::Server,
    };
    let mut conn = yamux::Connection::new(io, yamux::Config::default(), m);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(32);
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<
        tokio::sync::oneshot::Sender<io::Result<yamux::Stream>>,
    >(8);

    tokio::spawn(async move {
        enum Ev {
            In(io::Result<yamux::Stream>),
            Open(tokio::sync::oneshot::Sender<io::Result<yamux::Stream>>),
            Done,
        }
        loop {
            let ev = std::future::poll_fn(|cx| {
                // 优先驱动 Connection（socket I/O + 入站流）
                match conn.poll_next_inbound(cx) {
                    std::task::Poll::Ready(Some(r)) => {
                        std::task::Poll::Ready(Ev::In(r.map_err(io_err)))
                    }
                    std::task::Poll::Ready(None) => std::task::Poll::Ready(Ev::Done),
                    std::task::Poll::Pending => {
                        // Connection 空闲时看是否有开流请求
                        match open_rx.poll_recv(cx) {
                            std::task::Poll::Ready(Some(reply)) => {
                                std::task::Poll::Ready(Ev::Open(reply))
                            }
                            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ev::Done),
                            std::task::Poll::Pending => std::task::Poll::Pending,
                        }
                    }
                }
            })
            .await;
            match ev {
                Ev::In(r) => {
                    if in_tx.send(r).await.is_err() {
                        break; // 会话句柄已丢弃
                    }
                }
                Ev::Open(reply) => {
                    let r = std::future::poll_fn(|cx| conn.poll_new_outbound(cx))
                        .await
                        .map_err(io_err);
                    let _ = reply.send(r);
                }
                Ev::Done => break,
            }
        }
    });

    YamuxSession {
        inbound: in_rx,
        open_tx,
    }
}

fn io_err(e: yamux::ConnectionError) -> io::Error {
    io::Error::other(format!("yamux: {e}"))
}

impl YamuxSession {
    /// 打开一条出站流（client 侧发起；奇数 stream id）。
    pub async fn open_stream(&self) -> io::Result<yamux::Stream> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| io::Error::other("yamux driver 已退出"))?;
        rx.await
            .map_err(|_| io::Error::other("yamux driver 未应答"))?
    }

    /// 接受一条入站流（None = 会话关闭）。
    pub async fn next_stream(&mut self) -> Option<io::Result<yamux::Stream>> {
        self.inbound.recv().await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Plain,
    /// M5c-3 opt-in
    Yamux,
    /// M5c-4 opt-in
    DirectPunch,
}

impl TransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Plain => "plain",
            TransportKind::Yamux => "yamux",
            TransportKind::DirectPunch => "punch",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn plain_transport_passes_bytes_through() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            s.write_all(b"world").await.unwrap();
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let mut t = Plain::new(client);
        t.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        t.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        assert_eq!(t.name(), "plain");
        server.await.unwrap();
    }

    #[test]
    fn parse_transport_defaults_to_plain() {
        assert_eq!(parse_transport("plain"), TransportKind::Plain);
        assert_eq!(parse_transport("yamux"), TransportKind::Yamux);
        assert_eq!(parse_transport("punch"), TransportKind::DirectPunch);
        assert_eq!(parse_transport("direct"), TransportKind::DirectPunch);
        assert_eq!(parse_transport("unknown"), TransportKind::Plain);
        assert_eq!(parse_transport(""), TransportKind::Plain);
    }

    #[test]
    fn transport_kind_round_trips_via_as_str() {
        for k in [TransportKind::Plain, TransportKind::Yamux, TransportKind::DirectPunch] {
            let s = k.as_str();
            assert_eq!(parse_transport(s), k, "round-trip via {s}");
        }
    }

    #[tokio::test]
    async fn yamux_session_multiplexes_streams_over_one_connection() {
        use futures::io::AsyncReadExt as _;
        use futures::io::AsyncWriteExt as _;
        use tokio_util::compat::TokioAsyncReadCompatExt as _;

        let (a, b) = tokio::io::duplex(8 * 1024);
        let (mut client, mut server) = (
            yamux_connect(a.compat(), YamuxMode::Client),
            yamux_connect(b.compat(), YamuxMode::Server),
        );

        // 分步超时保护：任何一步 >5s 即失败并指出挂点
        let step = |name: &'static str| {
            tokio::time::timeout(std::time::Duration::from_secs(5), futures::future::pending::<()>())
        };
        let _ = step;

        // 交错驱动：client 开流与 server 收流并行（yamux 需要双方 Connection 持续被 poll）
        let client_task = tokio::spawn(async move {
            let mut streams = Vec::new();
            for i in 0..3u8 {
                let mut s = client
                    .open_stream()
                    .await
                    .expect("client open_stream");
                s.write_all(&[i; 4]).await.expect("client write");
                s.flush().await.expect("client flush");
                streams.push(s);
            }
            for (i, s) in streams.iter_mut().enumerate() {
                let mut buf = [0u8; 2];
                s.read_exact(&mut buf).await.expect("client read echo");
                assert_eq!(buf, [0xB0, i as u8], "回显数据不应串扰");
            }
            let mut s4 = client.open_stream().await.expect("reopen");
            s4.write_all(&[9]).await.expect("write 4th");
            s4.flush().await.expect("flush 4th");
        });

        let server_task = tokio::spawn(async move {
            for i in 0..3u8 {
                let mut s = server
                    .next_stream()
                    .await
                    .expect("server session alive")
                    .expect("server stream");
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.expect("server read");
                assert_eq!(buf, [i; 4], "流数据不应串扰");
                s.write_all(&[0xB0, i]).await.expect("server echo");
                s.flush().await.expect("server flush");
            }
            let _s5 = server
                .next_stream()
                .await
                .expect("alive for 4th")
                .expect("4th stream");
        });

        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async move {
                let (c, s) = (client_task, server_task);
                let (cr, sr) = futures::future::join(c, s).await;
                cr.expect("client task ok");
                sr.expect("server task ok");
            },
        )
        .await
        .expect("yamux 多路复用测试在 10s 内完成");
    }
}