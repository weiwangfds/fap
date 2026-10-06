//! fap 网关核心：设备注册表、隧道路由、流匹配、服务端接线。
pub mod acl;
pub mod admin;
pub mod admin_auth;
pub mod audit;
pub mod data_pool;
pub mod metrics;
pub mod protocol_http;
pub mod protocol_tls;
pub mod registry;
pub mod router;
pub mod shared_port;
pub mod store;
pub mod streams;
pub mod throttle;
pub mod server;

pub use server::{Gateway, GatewayConfig};
