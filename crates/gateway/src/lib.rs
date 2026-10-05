//! fap 网关核心：设备注册表、隧道路由、流匹配、服务端接线。
pub mod admin;
pub mod registry;
pub mod router;
pub mod streams;
pub mod store;
pub mod server;
pub mod shared_port;

pub use server::{Gateway, GatewayConfig};
