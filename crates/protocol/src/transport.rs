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
}