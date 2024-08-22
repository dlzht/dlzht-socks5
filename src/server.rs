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
//! ```
//! use async_trait::async_trait;
//! use dlzht_socks5::server::{PasswordAuthority, SocksServerBuilder};
//!
//! #[tokio::main]
//! async fn main() {
//!     let server = SocksServerBuilder::new()
//!         .custom_auth_pass()
//!         .build().unwrap();
//!     let _ = server.start().await;
//! }
//!
//! struct DatabaseAuthority {
//!   database: Database
//! }
//!
//! #[async_trait]
//! impl PasswordAuthority for DatabaseAuthority {
//!   async fn auth(&self, username: &[u8], password: &[u8]) -> Option<u64> {
//!     return self.database.select("SELECT id FROM account WHERE username = #{username} AND password = #{password}");
//!   }
//! }
//!
//! struct Database;
//! impl Database {
//!   fn select(&self, sql: &str) -> Option<u64> {
//!     todo!()
//!   }
//! }
//! ```

use crate::errors::{BuildSocksKind, ExecuteCmdKind, SocksError, SocksResult};
use crate::package::{read_package, write_package, AuthMethodsPackage, AuthSelectPackage, PasswordReqPackage, PasswordResPackage, RepliesPackage, RequestsPackage, UdpRequestsPackage};
use crate::{
  is_invalid_password, is_invalid_username, AuthMethod, PrivateStruct, RepliesRep,
  RequestCmd, SocksAddr, DEFAULT_SERVER_ADDR, DEFAULT_TIMEOUT,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

pub struct SocksServerBuilder {
  tcp_listen_addr: SocketAddr,
  tcp_reply_addr: SocketAddr,
  udp_listen_addr: Option<SocketAddr>,
  udp_reply_addr: Option<SocketAddr>,
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
      tcp_listen_addr: DEFAULT_SERVER_ADDR,
      tcp_reply_addr: DEFAULT_SERVER_ADDR,
      udp_listen_addr: None,
      udp_reply_addr: None,
      allow_auth_skip: false,
      allow_auth_pass: false,
      handshake_timeout: DEFAULT_TIMEOUT,
      memory_auth_pass: Default::default(),
      custom_auth_pass: None,
      _private: PrivateStruct,
    };
  }

  pub fn tcp_listen_addr(mut self, address: SocketAddr) -> Self {
    self.tcp_listen_addr = address;
    self.tcp_reply_addr = address;
    self
  }

  // pub fn tcp_reply_addr(mut self, address: SocketAddr) -> Self {
  //   self.tcp_reply_addr = address;
  //   self
  // }

  // pub fn udp_listen_addr(mut self, address: SocketAddr) -> Self {
  //   self.udp_listen_addr = Some(address);
  //   self.udp_reply_addr = Some(address);
  //   self
  // }

  // pub fn udp_reply_addr(mut self, address: SocketAddr) -> Self {
  //   self.udp_reply_addr = Some(address);
  //   self
  // }

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

  pub fn custom_auth_pass<T: PasswordAuthority>(mut self, authority: T) -> Self {
    self.allow_auth_pass = true;
    self.custom_auth_pass = Some(Box::new(authority));
    self
  }

  pub fn build(self) -> SocksResult<SocksServer> {
    let SocksServerBuilder {
      tcp_listen_addr: address,
      tcp_reply_addr,
      udp_listen_addr,
      udp_reply_addr,
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
    let server = SocksServer {
      tcp_listen_addr: address,
      tcp_reply_addr,
      udp_listen_addr,
      udp_reply_addr,
      udp_socket_map: RwLock::new(UdpSocketMap::default()),
      allow_auth_skip,
      allow_auth_pass,
      handshake_timeout,
      memory_auth_pass: DefaultAuthority::new(memory_auth_pass),
      custom_auth_pass,
      _private: PrivateStruct,
    };
    return Ok(server);
  }
}

pub struct SocksServer {
  tcp_listen_addr: SocketAddr,
  tcp_reply_addr: SocketAddr,
  udp_listen_addr: Option<SocketAddr>,
  udp_reply_addr: Option<SocketAddr>,
  udp_socket_map: RwLock<UdpSocketMap>,
  allow_auth_skip: bool,
  allow_auth_pass: bool,
  handshake_timeout: Duration,
  memory_auth_pass: DefaultAuthority,
  custom_auth_pass: Option<Box<dyn PasswordAuthority>>,
  _private: PrivateStruct,
}

async fn handle_tcp(server: Arc<SocksServer>) -> SocksResult<()> {
  let listener = TcpListener::bind(server.tcp_listen_addr).await?;
  loop {
    match listener.accept().await {
      Ok((stream, addr)) => {
        debug!("accept success: {}", addr);
        let server = server.clone();
        let timeout = server.handshake_timeout.clone();
        tokio::spawn(async move {
          let _ = server.handle_tcp_connection(addr, stream, timeout).await;
        });
      }
      Err(err) => {
        warn!("accept error: {}", err);
      }
    }
  }
}

async fn handle_udp(server: Arc<SocksServer>) -> SocksResult<()> {
  if server.udp_listen_addr.is_none() {
    return Ok(());
  }
  let mut peek_buf = BytesMut::with_capacity(16);
  let listen_addr = server.udp_listen_addr.unwrap();
  let socket = UdpSocket::bind(listen_addr).await?;
  loop {
    let (size, _addr) = socket.peek_from(&mut peek_buf).await?;
    let mut send_buf = BytesMut::with_capacity(size);
    match socket.recv_buf_from(&mut send_buf).await {
      Ok((_size, _addr)) => {
        match UdpRequestsPackage::read(send_buf) {
          Ok(pac) => {
            let target_addr = pac.addr_ref();
            let send_data = pac.data_ref();
            let _send_res = match target_addr {
              SocksAddr::IPV4(ipv4) => socket.send_to(send_data, ipv4).await,
              SocksAddr::IPV6(ipv6) => socket.send_to(send_data, ipv6).await,
              SocksAddr::Domain(domain, port) => socket.send_to(send_data, (domain.as_str(), *port)).await
            };
          }
          Err(err) => {
            error!("handle udp package error: {}", err);
          }
        }
      }
      Err(_) => {}
    }
  }
}

impl SocksServer {
  pub async fn start(self) -> SocksResult<()> {
    let server = Arc::new(self);

    if server.udp_listen_addr.is_some() {
      let udp_server = server.clone();
      tokio::spawn(async move {
        let _ = handle_udp(udp_server).await;
      });
    }

    let tcp_server = server.clone();
    let _ = handle_tcp(tcp_server).await;

    return Ok(());
  }

  async fn handle_tcp_connection(&self, addr: SocketAddr, stream: TcpStream, timeout: Duration) {
    match self.handshake_with_timeout(stream, timeout).await {
      Ok(mut connection) => {
        let _ = connection.transfer().await;
      }
      Err(err) => {
        warn!("socks handshake error: {} {}", addr, err);
      }
    }
  }

  async fn handshake_with_timeout(
    &self,
    stream: TcpStream,
    timeout: Duration,
  ) -> SocksResult<ServerConnection> {
    trace!("server handshake timeout: {:?}", timeout);
    return tokio::time::timeout(timeout, self.handshake_without_timeout(stream)).await?;
  }

  async fn handshake_without_timeout(
    &self,
    mut stream: TcpStream,
  ) -> SocksResult<ServerConnection> {
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr()?;
    let mut buffer = BytesMut::with_capacity(64);

    let auth_method = self.handle_select_method(&mut buffer, &mut stream).await?;
    let mut identifier = 0;
    if auth_method == AuthMethod::PASS {
      identifier = self.handle_password_auth(&mut buffer, &mut stream).await?;
    }
    let (command, addr) = self.handle_receive_requests(&mut buffer, &mut stream).await?;
    let source_stream = self.handle_execute_command(command, addr, &mut buffer, &mut stream).await?;

    let replies_pac = RepliesPackage::new(RepliesRep::SUCCESS, SocksAddr::UNSPECIFIED_ADDR);
    write_package(&replies_pac, &mut buffer, &mut stream).await?;

    let connection = ServerConnection {
      identifier,
      local_addr,
      peer_addr,
      auth_method,
      source_stream,
      target_stream: SocksStream::TCP(stream),
    };
    return Ok(connection);
  }

  async fn handle_select_method(&self, buffer: &mut BytesMut, stream: &mut TcpStream) -> SocksResult<AuthMethod> {
    let auth_methods_pac = read_package::<_, AuthMethodsPackage>(buffer, stream).await?;
    let auth_methods = auth_methods_pac.methods_ref();
    let auth_method = if self.allow_auth_skip && auth_methods.contains(&AuthMethod::SKIP) {
      AuthMethod::SKIP
    } else if self.allow_auth_pass && auth_methods.contains(&AuthMethod::PASS) {
      AuthMethod::PASS
    } else {
      AuthMethod::FAIL
    };
    if auth_method == AuthMethod::FAIL {
      let auth_select_pac = AuthSelectPackage::new(AuthMethod::FAIL);
      write_package(&auth_select_pac, buffer, stream).await?;
      return Err(SocksError::UnsupportedAuthMethod);
    }
    let auth_select_pac = AuthSelectPackage::new(auth_method);
    write_package(&auth_select_pac, buffer, stream).await?;
    return Ok(auth_method);
  }

  async fn handle_password_auth(&self, buffer: &mut BytesMut, stream: &mut TcpStream) -> SocksResult<u64> {
    let PasswordReqPackage { username, password } = read_package::<_, PasswordReqPackage>(buffer, stream).await?;
    let mut identifier = self.memory_auth_pass.auth(username.as_ref(), password.as_ref()).await;
    if let Some(authority) = &self.custom_auth_pass && identifier.is_none() {
      identifier = authority.auth(username.as_ref(), password.as_ref()).await;
    }
    if identifier.is_none() {
      let password_res_pac = PasswordResPackage::new(false);
      write_package(&password_res_pac, buffer, stream).await?;
      return Err(SocksError::PasswordAuthNotPassed);
    }
    let password_res_pac = PasswordResPackage::new(true);
    write_package(&password_res_pac, buffer, stream).await?;
    return Ok(identifier.unwrap_or(0));
  }

  async fn handle_receive_requests(&self, buffer: &mut BytesMut, stream: &mut TcpStream) -> SocksResult<(RequestCmd, SocksAddr)> {
    let requests_pac= read_package::<_, RequestsPackage>(buffer, stream).await?;
    let RequestsPackage { cmd, addr } = requests_pac;
    return Ok((cmd, addr));
  }

  async fn handle_execute_command(&self, cmd: RequestCmd, addr: SocksAddr, buffer: &mut BytesMut, stream: &mut TcpStream) -> SocksResult<SocksStream> {
    if cmd == RequestCmd::TCP {
      let stream = self.handle_command_tcp(&addr, buffer, stream).await?;
      return Ok(SocksStream::TCP(stream));
    }
    if cmd == RequestCmd::UDP {
      // return self.handle_command_udp(&addr, buffer, stream);
    }
    let replies_pac = RepliesPackage::new(
      RepliesRep::COMMAND_NOT_SUPPORTED,
      SocksAddr::UNSPECIFIED_ADDR,
    );
    write_package(&replies_pac, buffer, stream).await?;
    return Err(SocksError::UnsupportedCommand(cmd.to_byte()));
  }

  async fn handle_command_tcp(&self, addr: &SocksAddr, buffer: &mut BytesMut, stream: &mut TcpStream) -> SocksResult<TcpStream> {
    let target_stream = match self.connect_tcp_peer(&addr).await {
      Ok(stream) => stream,
      Err(SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err))) => {
        let replies_pac = RepliesPackage::new((&err).into(), SocksAddr::UNSPECIFIED_ADDR);
        write_package(&replies_pac, buffer, stream).await?;
        return Err(SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err)));
      }
      Err(err) => {
        return Err(err);
      }
    };
    return Ok(target_stream);
  }

  async fn handle_command_udp(&self, _addr: &SocksAddr, _buffer: &mut BytesMut, _stream: &mut TcpStream) {
    todo!()
  }

  async fn connect_tcp_peer(&self, addr: &SocksAddr) -> SocksResult<TcpStream> {
    let stream = match addr {
      SocksAddr::IPV4(ipv4) => TcpStream::connect(ipv4).await,
      SocksAddr::IPV6(ipv6) => TcpStream::connect(ipv6).await,
      SocksAddr::Domain(domain, port) => TcpStream::connect((domain.as_str(), *port)).await,
    };
    return stream.map_err(|err| SocksError::ExecuteCommandErr(ExecuteCmdKind::Server(err)));
  }
}

pub(crate) struct ServerConnection {
  identifier: u64,
  local_addr: SocketAddr,
  peer_addr: SocketAddr,
  auth_method: AuthMethod,
  source_stream: SocksStream,
  target_stream: SocksStream,
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
    match (&mut self.source_stream, &mut self.target_stream) {
      (SocksStream::TCP(source), SocksStream::TCP(target)) => {
        tokio::io::copy_bidirectional(source, target).await?;
      }
      _ => {
        unimplemented!()
      }
    }
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

#[derive(Debug, Default)]
struct UdpSocketMap {
  addrs: HashMap<SocketAddr, (SocketAddr, Instant)>,
}

impl UdpSocketMap {
  fn insert(&mut self, source: SocketAddr, target: SocketAddr) {
    let instant = Instant::now();
    let entry = self.addrs.entry(target)
      .or_insert((source, instant));
    entry.1 = instant;
  }

  fn query(&self, target: &SocketAddr) -> bool {
    return self.addrs.contains_key(target);
  }
}

struct UdpStream {
  stream: UdpSocket,
}

enum SocksStream {
  TCP(TcpStream),
  UDP
}
