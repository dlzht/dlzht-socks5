#![feature(io_error_more)]

//! ### Run server without any authorization
//!
//! ```
//! use dlzht_socks5::server::SocksServerBuilder;
//!
//! #[tokio::main]
//! async fn main() {
//!     let server = SocksServerBuilder::new()
//!         .allow_auth_skip(true)
//!         .build().unwrap();
//!     let _ = server.start().await;
//! }
//! ```
//!
//! Invoking `allow_auth_skip(true)`, server will support auth method `NO AUTHENTICATION REQUIRED`,
//! which means auth phase can be skipped.
//!
//!
//! ### Run server with password authorization
//!
//! ```
//! use dlzht_socks5::server::SocksServerBuilder;
//!
//! #[tokio::main]
//! async fn main() {
//!     let server = SocksServerBuilder::new()
//!         .credential(b"username", b"password")
//!         .build().unwrap();
//!     let _ = server.start().await;
//! }
//! ```
//!
//! Invoking `allow_auth_skip(true)`, server will support auth method `USERNAME/PASSWORD`,
//! `allow_auth_pass` will auto be set true(we can set false back to disable password auth).
//!
//! If we hava multiple username/password, then we can invoke `credential(...)` repeatedly,
//! or invoke `credentials(...)` for convenience.
//!
//! ### Run server with handshake timeout
//!
//! ```
//! use std::time::Duration;
//! use dlzht_socks5::server::SocksServerBuilder;
//!
//! #[tokio::main]
//! async fn main() {
//!     let server = SocksServerBuilder::new()
//!         .allow_auth_skip(true)
//!         .handshake_timeout(Duration::from_secs(1))
//!         .build().unwrap();
//!     let _ = server.start().await;
//! }
//! ```
//!
//! Default handshake timeout is 10 minutes, which almost means no timeout configured.
//!
//! ### Custom validate username/password
//!
//! Will support soon
//!
//! ### Run client without any authorization
//! ```
//! use dlzht_socks5::client::SocksClientBuilder;
//! use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
//!
//! #[tokio::main]
//! async fn main() {
//!     let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
//!     let mut client = SocksClientBuilder::new()
//!         .server_address(address)
//!         .allow_auth_skip(true)
//!         .build()
//!         .unwrap();
//!     let mut stream = client
//!         .connect(("127.0.0.1".to_string(), 9000))
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! ### Run client with password authorization
//!
//! ```
//! use dlzht_socks5::client::SocksClientBuilder;
//! use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
//!
//! #[tokio::main]
//! async fn main() {
//!     let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
//!     let mut client = SocksClientBuilder::new()
//!         .server_address(address)
//!         .credential(b"username", b"password")
//!         .build()
//!         .unwrap();
//!     let mut stream = client
//!         .connect(("127.0.0.1".to_string(), 9000))
//!         .await
//!         .unwrap();
//! }
//! ```

use crate::errors::{InvalidPackageKind, SocksError, SocksResult};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

pub(crate) const SOCKS5_RSV_BYTE: u8 = 0x00;
pub(crate) const SOCKS5_VERSION: u8 = 0x05;
pub(crate) const SUB_NEG_VERSION: u8 = 0x01;

pub(crate) const DEFAULT_SERVER_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Copy, Clone)]
pub(crate) struct PrivateStruct;

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Copy, Clone)]
pub(crate) struct AuthMethod(u8);

impl AuthMethod {
    pub const SKIP: AuthMethod = AuthMethod(0x00);
    pub const PASS: AuthMethod = AuthMethod(0x02);
    pub const FAIL: AuthMethod = AuthMethod(0xFF);
}

impl AuthMethod {
    fn from_byte(byte: u8) -> SocksResult<AuthMethod> {
        match byte {
            0x00 => Ok(AuthMethod::SKIP),
            0x02 => Ok(AuthMethod::PASS),
            _ => Ok(AuthMethod(byte)),
        }
    }

    pub fn to_byte(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthMethods {
    methods: Vec<AuthMethod>,
    _private: PrivateStruct,
}

impl AuthMethods {
    pub fn new() -> AuthMethods {
        return AuthMethods {
            methods: Vec::with_capacity(2),
            _private: PrivateStruct,
        };
    }

    pub fn insert(&mut self, method: AuthMethod) -> bool {
        return match self.methods.binary_search(&method) {
            Ok(_) => false,
            Err(index) => {
                self.methods.insert(index, method);
                true
            }
        };
    }

    pub fn contains(&self, method: &AuthMethod) -> bool {
        return self.methods.binary_search(method).is_ok();
    }

    pub fn len(&self) -> usize {
        return self.methods.len();
    }

    pub fn iter(&self) -> std::slice::Iter<'_, AuthMethod> {
        return self.methods.iter();
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Copy, Clone)]
pub(crate) struct RequestCmd(u8);

impl RequestCmd {
    pub const CONNECT: RequestCmd = RequestCmd(0x01);
    pub const BIND: RequestCmd = RequestCmd(0x02);
    pub const UDP: RequestCmd = RequestCmd(0x03);
}

impl RequestCmd {
    fn from_byte(byte: u8) -> SocksResult<RequestCmd> {
        match byte {
            0x01 => Ok(RequestCmd::CONNECT),
            0x02 => Ok(RequestCmd::BIND),
            0x03 => Ok(RequestCmd::UDP),
            _ => Err(SocksError::InvalidPackageErr(
                InvalidPackageKind::InvalidRequestsCmd(byte),
            )),
        }
    }

    fn to_byte(&self) -> u8 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Copy, Clone)]
pub(crate) struct RepliesRep(u8);

impl RepliesRep {
    pub const SUCCESS: RepliesRep = RepliesRep(0x00);
    pub const SOCKS_SERVER_FAILURE: RepliesRep = RepliesRep(0x01);
    pub const NOT_ALLOWED_BY_RULESET: RepliesRep = RepliesRep(0x02);
    pub const NETWORK_UNREACHABLE: RepliesRep = RepliesRep(0x03);
    pub const HOST_UNREACHABLE: RepliesRep = RepliesRep(0x04);
    pub const CONNECTION_REFUSED: RepliesRep = RepliesRep(0x05);
    pub const TTL_EXPIRED: RepliesRep = RepliesRep(0x06);
    pub const COMMAND_NOT_SUPPORTED: RepliesRep = RepliesRep(0x07);
    pub const ADDR_TYPE_NOT_SUPPORTED: RepliesRep = RepliesRep(0x08);
}

impl RepliesRep {
    fn message(&self) -> &'static str {
        match self {
            &RepliesRep::SUCCESS => "succeeded",
            &RepliesRep::SOCKS_SERVER_FAILURE => "general SOCKS server failure",
            &RepliesRep::NOT_ALLOWED_BY_RULESET => "connection not allowed by ruleset",
            &RepliesRep::NETWORK_UNREACHABLE => "network unreachable",
            &RepliesRep::HOST_UNREACHABLE => "host unreachable",
            &RepliesRep::CONNECTION_REFUSED => "connection refused",
            &RepliesRep::TTL_EXPIRED => "TTL expired",
            &RepliesRep::COMMAND_NOT_SUPPORTED => "command not supported",
            &RepliesRep::ADDR_TYPE_NOT_SUPPORTED => "address type not supported",
            _ => "unassigned",
        }
    }
}

impl From<&std::io::Error> for RepliesRep {
    fn from(value: &std::io::Error) -> Self {
        match value.kind() {
            ErrorKind::NetworkUnreachable
            | ErrorKind::AddrNotAvailable
            | ErrorKind::NetworkDown => RepliesRep::NETWORK_UNREACHABLE,
            ErrorKind::HostUnreachable => RepliesRep::HOST_UNREACHABLE,
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused => RepliesRep::CONNECTION_REFUSED,
            ErrorKind::TimedOut => RepliesRep::TTL_EXPIRED,
            _ => RepliesRep::SOCKS_SERVER_FAILURE,
        }
    }
}

impl RepliesRep {
    fn from_byte(byte: u8) -> SocksResult<RepliesRep> {
        match byte {
            0x00 => Ok(RepliesRep::SUCCESS),
            0x01 => Ok(RepliesRep::SOCKS_SERVER_FAILURE),
            0x02 => Ok(RepliesRep::NOT_ALLOWED_BY_RULESET),
            0x03 => Ok(RepliesRep::NETWORK_UNREACHABLE),
            0x04 => Ok(RepliesRep::HOST_UNREACHABLE),
            0x05 => Ok(RepliesRep::CONNECTION_REFUSED),
            0x06 => Ok(RepliesRep::TTL_EXPIRED),
            0x07 => Ok(RepliesRep::COMMAND_NOT_SUPPORTED),
            0x08 => Ok(RepliesRep::ADDR_TYPE_NOT_SUPPORTED),
            _ => Ok(RepliesRep(byte)),
        }
    }

    pub fn to_byte(&self) -> u8 {
        self.0
    }
}

/// three type of address SOCKS5 support
/// 1. 0x01: Ipv4Addr + port
/// 2. 0x04: Ipv6Addr + port
/// 3. 0x03: DomainName + port
#[derive(Debug)]
pub enum SocksAddr {
    IPV4(SocketAddrV4),
    IPV6(SocketAddrV6),
    Domain(String, u16),
}

impl SocksAddr {
    /// type of Ipv4Addr is 0x01
    pub const KIND_IPV4: u8 = 0x01;

    /// type of Ipv6Addr is 0x01
    pub const KIND_IPV6: u8 = 0x04;

    /// type of DomainName is 0x01
    pub const KIND_DOMAIN: u8 = 0x03;

    pub const UNSPECIFIED_ADDR: SocksAddr =
        SocksAddr::IPV4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
}

impl SocksAddr {
    pub fn addr_type(&self) -> u8 {
        match self {
            SocksAddr::IPV4(_) => 0x01,
            SocksAddr::IPV6(_) => 0x04,
            SocksAddr::Domain(_, _) => 0x03,
        }
    }
}

/// convert trait from `SocketAddr` to [`SocksAddr`]
pub trait ToSocksAddress {
    /// convert `std::net::SocketAddrV4`, `std::net::SocketAddrV4`, or `DomainName + Port` to Socks5Addr
    fn to_socks_addr(self) -> SocksAddr;
}

impl ToSocksAddress for SocketAddrV4 {
    fn to_socks_addr(self) -> SocksAddr {
        return SocksAddr::IPV4(self);
    }
}

impl ToSocksAddress for SocketAddrV6 {
    fn to_socks_addr(self) -> SocksAddr {
        return SocksAddr::IPV6(self);
    }
}

impl ToSocksAddress for (String, u16) {
    fn to_socks_addr(self) -> SocksAddr {
        return SocksAddr::Domain(self.0, self.1);
    }
}

impl ToSocksAddress for SocketAddr {
    fn to_socks_addr(self) -> SocksAddr {
        return match self {
            SocketAddr::V4(addr) => SocksAddr::IPV4(addr),
            SocketAddr::V6(addr) => SocksAddr::IPV6(addr),
        };
    }
}

pub(crate) fn is_invalid_username(username: &[u8]) -> bool {
    return username.is_empty() || username.len() > 255;
}

pub(crate) fn is_invalid_password(password: &[u8]) -> bool {
    return password.is_empty() || password.len() > 255;
}

pub mod client;
pub mod errors;
mod package;
pub mod server;
