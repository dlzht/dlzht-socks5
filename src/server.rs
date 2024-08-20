//! server module include [`SocksServerBuilder`] and [`SocksServer`]
//!
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

use crate::errors::{BuildSocksKind, ExecuteCmdKind, InvalidPackageKind, SocksError, SocksResult};
use crate::package::{
  read_package, write_package, AuthMethodsPackage, AuthSelectPackage, PasswordReqPackage,
  PasswordResPackage, RepliesPackage, RequestsPackage,
};
use crate::{
  is_invalid_password, is_invalid_username, AuthMethod, AuthMethods, PrivateStruct, RepliesRep,
  RequestCmd, SocksAddr, DEFAULT_SERVER_ADDR, DEFAULT_TIMEOUT,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, trace, warn};

pub struct SocksServerBuilder {
  server_address: SocketAddr,
  allow_auth_skip: bool,
  allow_auth_pass: bool,
  handshake_timeout: Duration,
  memory_auth_pass: HashMap<Bytes, Bytes>,
  custom_auth_pass: Option<Box<dyn PasswordAuthority>>,
  _private: PrivateStruct,
}

impl SocksServerBuilder {
  pub fn new() -> SocksServerBuilder {
    return SocksServerBuilder {
      server_address: DEFAULT_SERVER_ADDR,
      allow_auth_skip: false,
      allow_auth_pass: false,
      handshake_timeout: DEFAULT_TIMEOUT,
      memory_auth_pass: Default::default(),
      custom_auth_pass: None,
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

  pub fn allow_auth_pass(mut self, allow: bool) -> Self {
    self.allow_auth_pass = allow;
    self
  }

  pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
    self.handshake_timeout = timeout;
    self
  }

  pub fn credential(mut self, username: &[u8], password: &[u8]) -> Self {
    self.allow_auth_pass = true;
    self.memory_auth_pass.insert(
      Bytes::copy_from_slice(username.as_ref()),
      Bytes::copy_from_slice(password.as_ref()),
    );
    self
  }

  pub fn credentials(mut self, credentials: HashMap<Bytes, Bytes>) -> Self {
    self.allow_auth_pass = true;
    self.memory_auth_pass.extend(credentials);
    self
  }

  pub fn custom_auth_pass<T: PasswordAuthority>(&mut self, authority: T) -> &mut Self {
    self.custom_auth_pass = Some(Box::new(authority));
    self
  }

  pub fn build(self) -> SocksResult<SocksServer> {
    let SocksServerBuilder {
      server_address: address,
      allow_auth_skip,
      allow_auth_pass,
      handshake_timeout,
      memory_auth_pass,
      custom_auth_pass,
      _private,
    } = self;

    if !allow_auth_skip && !allow_auth_pass {
      return Err(SocksError::BuildSocksServerErr(
        BuildSocksKind::InvalidAuthMethod,
      ));
    }

    for (username, password) in memory_auth_pass.iter() {
      if is_invalid_username(username.as_ref()) {
        return Err(SocksError::BuildSocksServerErr(
          BuildSocksKind::InvalidUsername,
        ));
      }
      if is_invalid_password(password.as_ref()) {
        return Err(SocksError::BuildSocksServerErr(
          BuildSocksKind::InvalidPassword,
        ));
      }
    }
    let authority = DefaultAuthority::new(memory_auth_pass);

    let server = SocksServer {
      address,
      allow_auth_skip,
      allow_auth_pass,
      handshake_timeout,
      memory_auth_pass: authority,
      custom_auth_pass,
      _private: PrivateStruct,
    };
    return Ok(server);
  }
}

pub struct SocksServer {
  address: SocketAddr,
  allow_auth_skip: bool,
  allow_auth_pass: bool,
  handshake_timeout: Duration,
  memory_auth_pass: DefaultAuthority,
  custom_auth_pass: Option<Box<dyn PasswordAuthority>>,
  _private: PrivateStruct,
}

impl SocksServer {
  pub async fn start(self) -> SocksResult<()> {
    let listener = TcpListener::bind(self.address).await?;
    let server = Arc::new(self);
    loop {
      match listener.accept().await {
        Err(err) => {
          warn!("accept error: {}", err);
        }
        Ok((stream, addr)) => {
          debug!("accept success: {}", addr);
          let server = server.clone();
          let timeout = server.handshake_timeout.clone();
          tokio::spawn(async move {
            match server.handshake_timeout(stream, timeout).await {
              Ok(mut connection) => {
                let _ = connection.transfer().await;
              }
              Err(err) => {
                warn!("socks handshake error: {} {}", addr, err);
              }
            }
          });
        }
      }
    }
  }

  async fn handshake_timeout(
    &self,
    stream: TcpStream,
    timeout: Duration,
  ) -> SocksResult<ServerConnection> {
    trace!("server handshake timeout: {:?}", timeout);
    return tokio::time::timeout(timeout, self.handshake(stream)).await?;
  }

  async fn handshake(&self, mut stream: TcpStream) -> SocksResult<ServerConnection> {
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr()?;
    let mut buffer = BytesMut::with_capacity(64);

    let auth_methods_pac: AuthMethodsPackage = read_package(&mut buffer, &mut stream).await?;
    let auth_method = self
      .select_auth_method(auth_methods_pac.methods_ref())
      .unwrap_or(AuthMethod::FAIL);
    if auth_method == AuthMethod::FAIL {
      let auth_select_pac = AuthSelectPackage::new(AuthMethod::FAIL);
      write_package(&auth_select_pac, &mut buffer, &mut stream).await?;
      return Err(SocksError::UnsupportedAuthMethod);
    }

    let auth_select_pac = AuthSelectPackage::new(auth_method);
    write_package(&auth_select_pac, &mut buffer, &mut stream).await?;

    let mut identifier = 0;
    if auth_method == AuthMethod::PASS {
      let password_req_pac: PasswordReqPackage = read_package(&mut buffer, &mut stream).await?;
      let authed = self
        .process_pass_auth(
          password_req_pac.username_ref(),
          password_req_pac.password_ref(),
        )
        .await;
      if authed.is_none() {
        let password_res_pac = PasswordResPackage::new(false);
        write_package(&password_res_pac, &mut buffer, &mut stream).await?;
        return Err(SocksError::PasswordAuthNotPassed);
      }
      identifier = authed.unwrap_or(0);
      let password_res_pac = PasswordResPackage::new(true);
      write_package(&password_res_pac, &mut buffer, &mut stream).await?;
    }

    let requests_pac: RequestsPackage = match read_package(&mut buffer, &mut stream).await {
      Ok(pac) => pac,
      Err(err) => {
        if matches!(
          err,
          SocksError::InvalidPackageErr(InvalidPackageKind::InvalidRequestsCmd(_))
        ) {
          let replies_pac = RepliesPackage::new(
            RepliesRep::COMMAND_NOT_SUPPORTED,
            SocksAddr::UNSPECIFIED_ADDR,
          );
          write_package(&replies_pac, &mut buffer, &mut stream).await?;
        }
        return Err(err);
      }
    };
    if &RequestCmd::CONNECT != requests_pac.cmd_ref() {
      let replies_pac = RepliesPackage::new(
        RepliesRep::COMMAND_NOT_SUPPORTED,
        SocksAddr::UNSPECIFIED_ADDR,
      );
      write_package(&replies_pac, &mut buffer, &mut stream).await?;
      return Err(SocksError::UnsupportedCommand(
        requests_pac.cmd_ref().to_byte(),
      ));
    }
    let target_stream = match self.connect_target_peer(requests_pac.addr_ref()).await {
      Ok(stream) => stream,
      Err(SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err))) => {
        let replies_pac = RepliesPackage::new((&err).into(), SocksAddr::UNSPECIFIED_ADDR);
        write_package(&replies_pac, &mut buffer, &mut stream).await?;
        return Err(SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err)));
      }
      Err(err) => {
        return Err(err);
      }
    };
    let replies_pac = RepliesPackage::new(RepliesRep::SUCCESS, SocksAddr::UNSPECIFIED_ADDR);
    write_package(&replies_pac, &mut buffer, &mut stream).await?;

    let connection = ServerConnection {
      identifier,
      local_addr,
      peer_addr,
      auth_method,
      proxy_stream: stream,
      target_stream,
    };
    return Ok(connection);
  }

  fn select_auth_method(&self, methods: &AuthMethods) -> Option<AuthMethod> {
    if self.allow_auth_skip && methods.contains(&AuthMethod::SKIP) {
      return Some(AuthMethod::SKIP);
    }
    if self.allow_auth_pass && methods.contains(&AuthMethod::PASS) {
      return Some(AuthMethod::PASS);
    }
    return None;
  }

  async fn process_pass_auth(&self, username: &[u8], password: &[u8]) -> Option<u64> {
    let res = self.memory_auth_pass.auth(username, password).await;
    if res.is_some() {
      return res;
    }
    return match &self.custom_auth_pass {
      None => None,
      Some(authority) => authority.auth(username, password).await,
    };
  }

  async fn connect_target_peer(&self, addr: &SocksAddr) -> SocksResult<TcpStream> {
    let stream = match addr {
      SocksAddr::IPV4(ipv4) => TcpStream::connect(ipv4).await,
      SocksAddr::IPV6(ipv6) => TcpStream::connect(ipv6).await,
      SocksAddr::Domain(domain, port) => TcpStream::connect((domain.as_str(), *port)).await,
    };
    return stream.map_err(|err| SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err)));
  }
}

#[derive(Debug)]
pub(crate) struct ServerConnection {
  identifier: u64,
  local_addr: SocketAddr,
  peer_addr: SocketAddr,
  auth_method: AuthMethod,
  proxy_stream: TcpStream,
  target_stream: TcpStream,
}

impl ServerConnection {
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

  async fn transfer(&mut self) -> SocksResult<()> {
    tokio::io::copy_bidirectional(&mut self.proxy_stream, &mut self.target_stream).await?;
    return Ok(());
  }
}

#[async_trait]
pub trait PasswordAuthority: Send + Sync + 'static {
  async fn auth(&self, username: &[u8], password: &[u8]) -> Option<u64>;
}

pub(crate) struct DefaultAuthority {
  passwords: HashMap<Bytes, Bytes>,
}

impl DefaultAuthority {
  pub fn new(passwords: HashMap<Bytes, Bytes>) -> DefaultAuthority {
    return DefaultAuthority { passwords };
  }
}

#[async_trait]
impl PasswordAuthority for DefaultAuthority {
  async fn auth(&self, username: &[u8], password: &[u8]) -> Option<u64> {
    let result = self
      .passwords
      .get(username)
      .map(|p| p == password)
      .unwrap_or(false);
    return if result { Some(1) } else { None };
  }
}
