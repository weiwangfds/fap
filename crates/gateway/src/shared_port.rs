//! 共享单端口（M3/M4）：HTTP 后缀路由 / SNI 路由 / 访问器协议。
//! M3 实现：首包嗅探分流。此文件当前为 M2 编译桩。

use std::net::SocketAddr;

use crate::server::State;

/// 受理共享端口连接：嗅探首包并按规则分流。
pub(crate) async fn serve(listener: tokio::net::TcpListener, _addr: SocketAddr, _state: State) {
    // M3：首包嗅探 + HTTP/SNI/访问器分流
    let _ = listener;
}
