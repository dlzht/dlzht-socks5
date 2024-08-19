//! client module include [`SocksClientBuilder`] and [`SocksClient`]
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

use crate::errors::{BuildSocksKind, ExecuteCmdKind, SocksError, SocksResult};
use crate::package::{
    read_package, write_package, AuthMethodsPackage, AuthSelectPackage, PasswordReqPackage,
    PasswordResPackage, RepliesPackage, RequestsPackage,
};
use crate::{
    is_invalid_password, is_invalid_username, AuthMethod, AuthMethods, PrivateStruct, RepliesRep,
    RequestCmd, ToSocksAddress, DEFAULT_SERVER_ADDR,
};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::error;

pub struct SocksClientBuilder {
    server_address: SocketAddr,
    allow_auth_skip: bool,
    allow_auth_pass: bool,
    username: Option<Bytes>,
    password: Option<Bytes>,
    _private: PrivateStruct,
}

impl SocksClientBuilder {
    pub fn new() -> SocksClientBuilder {
        return SocksClientBuilder {
            server_address: DEFAULT_SERVER_ADDR,
            allow_auth_skip: true,
            allow_auth_pass: false,
            username: None,
            password: None,
            _private: PrivateStruct,
        };
    }

    pub fn server_address(mut self, address: SocketAddr) -> Self {
        self.server_address = address;
        self
    }

    pub fn allow_auth_skip(mut self, allow: bool) -> Self {
        self.allow_auth_skip = allow;
        self
    }

    pub fn credential(mut self, username: &[u8], password: &[u8]) -> Self {
        self.allow_auth_pass = true;
        self.username = Some(Bytes::copy_from_slice(username));
        self.password = Some(Bytes::copy_from_slice(password));
        self
    }

    pub fn build(self) -> SocksResult<SocksClient> {
        let SocksClientBuilder {
            server_address,
            allow_auth_skip,
            allow_auth_pass,
            username,
            password,
            _private,
        } = self;
        let mut methods = AuthMethods::new();
        if allow_auth_skip {
            methods.insert(AuthMethod::SKIP);
        }
        if allow_auth_pass {
            if username
                .as_ref()
                .map(|v| is_invalid_username(v.as_ref()))
                .unwrap_or(true)
            {
                return Err(SocksError::BuildSocksClientErr(
                    BuildSocksKind::InvalidUsername,
                ));
            }
            if password
                .as_ref()
                .map(|v| is_invalid_password(v.as_ref()))
                .unwrap_or(true)
            {
                return Err(SocksError::BuildSocksClientErr(
                    BuildSocksKind::InvalidPassword,
                ));
            }
            methods.insert(AuthMethod::PASS);
        }
        if methods.len() == 0 {
            return Err(SocksError::BuildSocksClientErr(
                BuildSocksKind::InvalidAuthMethod,
            ));
        }
        let client = SocksClient {
            server_addr: server_address,
            auth_methods: methods,
            username,
            password,
            _private: PrivateStruct,
        };
        return Ok(client);
    }
}

pub struct SocksClient {
    server_addr: SocketAddr,
    auth_methods: AuthMethods,
    username: Option<Bytes>,
    password: Option<Bytes>,
    _private: PrivateStruct,
}

impl SocksClient {
    pub async fn connect(&mut self, addr: impl ToSocksAddress) -> SocksResult<TcpStream> {
        let connection = self.handshake(addr, RequestCmd::CONNECT).await?;
        return Ok(connection.proxy_stream);
    }

    async fn handshake(
        &mut self,
        addr: impl ToSocksAddress,
        cmd: RequestCmd,
    ) -> SocksResult<ClientConnection> {
        let mut stream = TcpStream::connect(self.server_addr).await?;
        let local_addr = stream.local_addr()?;
        let peer_addr = stream.peer_addr()?;

        let mut buffer = BytesMut::with_capacity(512);

        let methods_pac = AuthMethodsPackage::new(self.auth_methods.clone());
        write_package(&methods_pac, &mut buffer, &mut stream).await?;

        let select_pac: AuthSelectPackage = read_package(&mut buffer, &mut stream).await?;
        let method = select_pac.auth_method();
        if !self.auth_methods.contains(&method) {
            return Err(SocksError::UnsupportedAuthMethod);
        }

        if method == AuthMethod::PASS {
            let password_pac = PasswordReqPackage::new(
                self.username.as_ref().unwrap(),
                self.password.as_ref().unwrap(),
            );
            write_package(&password_pac, &mut buffer, &mut stream).await?;

            let password_pac: PasswordResPackage = read_package(&mut buffer, &mut stream).await?;
            if !password_pac.is_success() {
                return Err(SocksError::PasswordAuthNotPassed);
            }
        }
        let requests_pac = RequestsPackage::new(cmd, addr.to_socks_addr());
        write_package(&requests_pac, &mut buffer, &mut stream).await?;

        let replies_pac: RepliesPackage = read_package(&mut buffer, &mut stream).await?;
        if !replies_pac.is_success() {
            let rep = RepliesRep::from_byte(replies_pac.req_ref().to_byte())?;
            error!("handshake replies error: {}", rep.message());
            return Err(SocksError::ExecuteCommandErr(ExecuteCmdKind::Client(
                rep.to_byte(),
            )));
        }
        let stream = ClientConnection {
            identifier: 0,
            local_addr,
            peer_addr,
            auth_method: AuthMethod::SKIP,
            proxy_stream: stream,
        };
        return Ok(stream);
    }
}

#[derive(Debug)]
pub(crate) struct ClientConnection {
    identifier: u64,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    auth_method: AuthMethod,
    proxy_stream: TcpStream,
}

impl ClientConnection {
    #[allow(dead_code)]
    fn identifier(&self) -> u64 {
        return self.identifier;
    }

    #[allow(dead_code)]
    fn local_addr(&self) -> SocketAddr {
        return self.local_addr;
    }

    #[allow(dead_code)]
    fn peer_addr(&self) -> SocketAddr {
        return self.peer_addr;
    }

    #[allow(dead_code)]
    fn auth_method(&self) -> AuthMethod {
        return self.auth_method;
    }
}
