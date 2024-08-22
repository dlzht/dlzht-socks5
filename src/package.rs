use crate::errors::{InvalidPackageKind, SocksError, SocksResult};
use crate::{
  AuthMethod, AuthMethods, RepliesRep, RequestCmd, SocksAddr, SOCKS5_RSV_BYTE, SOCKS5_VERSION,
  SUB_NEG_VERSION,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

#[derive(Debug)]
pub(crate) enum ParseResult<T> {
  Partial,
  Complete(T),
}


pub(crate) trait SocksPackage: Sized + Debug {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>>;
  fn write(&self, buffer: &mut BytesMut);
}

#[derive(Debug)]
pub(crate) struct AuthMethodsPackage {
  methods: AuthMethods,
}

impl AuthMethodsPackage {
  pub fn new(methods: AuthMethods) -> AuthMethodsPackage {
    return AuthMethodsPackage { methods };
  }

  pub fn methods_ref(&self) -> &AuthMethods {
    return &self.methods;
  }
}

impl SocksPackage for AuthMethodsPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    let mut bytes = buffer.as_ref();
    if bytes.len() <= 2 {
      return Ok(ParseResult::Partial);
    }
    let mut advance = 0;
    let version = bytes.get_u8();
    if version != SOCKS5_VERSION {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5Version(version),
      ));
    }
    let num = bytes.get_u8() as usize;
    advance += 2;
    if num <= 0 {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidAuthMethodNum(num as u8),
      ));
    }
    if bytes.len() < num {
      return Ok(ParseResult::Partial);
    }
    let mut methods = AuthMethods::new();
    for _ in 0..num {
      let method_byte = bytes.get_u8();
      let method = AuthMethod::from_byte(method_byte)?;
      if !methods.insert(method) {
        return Err(SocksError::InvalidPackageErr(
          InvalidPackageKind::DuplicatedAuthMethod(method_byte),
        ));
      }
    }
    advance += num;
    buffer.advance(advance);
    return Ok(ParseResult::Complete(AuthMethodsPackage::new(methods)));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SOCKS5_VERSION);
    buffer.put_u8(self.methods.len() as u8);
    for method in self.methods.iter() {
      buffer.put_u8(method.to_byte());
    }
  }
}

#[derive(Debug)]
pub(crate) struct AuthSelectPackage {
  method: AuthMethod,
}

impl AuthSelectPackage {
  pub fn new(method: AuthMethod) -> AuthSelectPackage {
    return AuthSelectPackage { method };
  }

  pub fn auth_method(&self) -> AuthMethod {
    return self.method;
  }
}

impl SocksPackage for AuthSelectPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    let mut bytes = buffer.as_ref();
    if bytes.len() < 2 {
      return Ok(ParseResult::Partial);
    }
    let version = bytes.get_u8();
    if version != SOCKS5_VERSION {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5Version(version),
      ));
    }
    let method = AuthMethod::from_byte(bytes.get_u8())?;
    buffer.advance(2);
    return Ok(ParseResult::Complete(AuthSelectPackage { method }));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SOCKS5_VERSION);
    buffer.put_u8((&self.method).to_byte());
  }
}

#[derive(Debug)]
pub(crate) struct PasswordReqPackage {
  pub(crate) username: Bytes,
  pub(crate) password: Bytes,
}

impl PasswordReqPackage {
  pub fn new<U: AsRef<[u8]>, P: AsRef<[u8]>>(username: U, password: P) -> PasswordReqPackage {
    return PasswordReqPackage {
      username: Bytes::copy_from_slice(username.as_ref()),
      password: Bytes::copy_from_slice(password.as_ref()),
    };
  }

}

impl SocksPackage for PasswordReqPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    let mut bytes = buffer.as_ref();
    let mut advance = 0;
    if bytes.len() < 3 {
      return Ok(ParseResult::Partial);
    }
    let version = bytes.get_u8();
    advance += 1;
    if version != SUB_NEG_VERSION {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSubNegVersion(version),
      ));
    }
    let username_len = bytes.get_u8() as usize;
    advance += 1;
    if username_len <= 0 {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidUsernameLength(username_len as u8),
      ));
    }
    if bytes.len() <= username_len {
      return Ok(ParseResult::Partial);
    }
    advance += username_len;
    let username = Bytes::copy_from_slice(&bytes[..username_len]);
    bytes.advance(username_len);
    let password_len = bytes.get_u8() as usize;
    advance += 1;
    if password_len <= 0 {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidPasswordLength(password_len as u8),
      ));
    }
    if bytes.len() < password_len {
      return Ok(ParseResult::Partial);
    }
    advance += password_len;
    let password = Bytes::copy_from_slice(&bytes[..password_len]);
    bytes.advance(password_len);
    buffer.advance(advance);
    let package = PasswordReqPackage { username, password };
    return Ok(ParseResult::Complete(package));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SUB_NEG_VERSION);
    buffer.put_u8(self.username.len() as u8);
    buffer.put_slice(self.username.as_ref());
    buffer.put_u8(self.password.len() as u8);
    buffer.put_slice(self.password.as_ref());
  }
}

#[derive(Debug)]
pub(crate) struct PasswordResPackage {
  status: bool,
}

impl PasswordResPackage {
  pub fn new(status: bool) -> PasswordResPackage {
    return PasswordResPackage { status };
  }

  pub fn is_success(&self) -> bool {
    return self.status;
  }
}

impl SocksPackage for PasswordResPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    let mut bytes = buffer.as_ref();
    if bytes.len() < 2 {
      return Ok(ParseResult::Partial);
    }
    let version = bytes.get_u8();
    if SUB_NEG_VERSION != version {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSubNegVersion(version),
      ));
    }
    let status = if bytes.get_u8() == 0 { true } else { false };
    buffer.advance(2);
    return Ok(ParseResult::Complete(PasswordResPackage { status }));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SUB_NEG_VERSION);
    buffer.put_u8(if self.status { 0x00 } else { 0x01 });
  }
}

#[derive(Debug)]
pub(crate) struct RequestsPackage {
  pub(crate) cmd: RequestCmd,
  pub(crate) addr: SocksAddr,
}

impl RequestsPackage {
  pub fn new(cmd: RequestCmd, addr: SocksAddr) -> RequestsPackage {
    return RequestsPackage { cmd, addr };
  }
}

impl SocksPackage for RequestsPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    if buffer.len() < 8 {
      return Ok(ParseResult::Partial);
    }
    let mut bytes = buffer.as_ref();
    let mut advance = 0;
    let version = bytes.get_u8();
    if version != SOCKS5_VERSION {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5Version(version),
      ));
    }
    let cmd = bytes.get_u8();
    let cmd = RequestCmd::from_byte(cmd)?;
    let rsv = bytes.get_u8();
    if rsv != SOCKS5_RSV_BYTE {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5RsvByte(rsv),
      ));
    }
    advance += 3;
    let addr = match read_address(&mut bytes, &mut advance)? {
      ParseResult::Partial => {
        return Ok(ParseResult::Partial);
      }
      ParseResult::Complete(addr) => addr,
    };
    buffer.advance(advance);
    let package = RequestsPackage { cmd, addr };
    return Ok(ParseResult::Complete(package));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SOCKS5_VERSION);
    buffer.put_u8(self.cmd.to_byte());
    buffer.put_u8(SOCKS5_RSV_BYTE);
    write_address(buffer, &self.addr);
  }
}

#[derive(Debug)]
pub(crate) struct RepliesPackage {
  rep: RepliesRep,
  addr: SocksAddr,
}

impl RepliesPackage {
  pub fn new(rep: RepliesRep, addr: SocksAddr) -> RepliesPackage {
    return RepliesPackage { rep, addr };
  }

  pub fn req_ref(&self) -> &RepliesRep {
    return &self.rep;
  }

  pub fn is_success(&self) -> bool {
    return self.rep == RepliesRep::SUCCESS;
  }
}

impl SocksPackage for RepliesPackage {
  fn read(buffer: &mut BytesMut) -> SocksResult<ParseResult<Self>> {
    if buffer.len() < 8 {
      return Ok(ParseResult::Partial);
    }
    let mut bytes = buffer.as_ref();
    let mut advance = 0;
    let version = bytes.get_u8();
    if SOCKS5_VERSION != version {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5Version(version),
      ));
    }
    let rep = bytes.get_u8();
    let rep = RepliesRep::from_byte(rep)?;
    let rsv = bytes.get_u8();
    if rsv != SOCKS5_RSV_BYTE {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidSocks5RsvByte(rsv),
      ));
    }
    advance += 3;
    let addr = match read_address(&mut bytes, &mut advance)? {
      ParseResult::Partial => {
        return Ok(ParseResult::Partial);
      }
      ParseResult::Complete(addr) => addr,
    };
    buffer.advance(advance);
    let package = RepliesPackage { rep, addr };
    return Ok(ParseResult::Complete(package));
  }

  fn write(&self, buffer: &mut BytesMut) {
    buffer.put_u8(SOCKS5_VERSION);
    buffer.put_u8(self.rep.to_byte());
    buffer.put_u8(SOCKS5_RSV_BYTE);
    write_address(buffer, &self.addr);
  }
}

fn read_address(mut bytes: &[u8], advance: &mut usize) -> SocksResult<ParseResult<SocksAddr>> {
  let addr_type = bytes.get_u8();
  *advance += 1;
  let addr = match addr_type {
    SocksAddr::KIND_IPV4 => {
      if bytes.len() < 6 {
        return Ok(ParseResult::Partial);
      }
      let addr = bytes.get_u32();
      let port = bytes.get_u16();
      *advance += 6;
      SocksAddr::IPV4(SocketAddrV4::new(Ipv4Addr::from_bits(addr), port))
    }
    SocksAddr::KIND_IPV6 => {
      if bytes.len() < 18 {
        return Ok(ParseResult::Partial);
      }
      let addr = bytes.get_u128();
      let port = bytes.get_u16();
      *advance += 18;
      SocksAddr::IPV6(SocketAddrV6::new(Ipv6Addr::from_bits(addr), port, 0, 0))
    }
    SocksAddr::KIND_DOMAIN => {
      let addr_len = bytes.get_u8() as usize;
      if bytes.len() < addr_len + 2 {
        return Ok(ParseResult::Partial);
      }
      let mut domain = Vec::with_capacity(addr_len);
      domain.extend_from_slice(&bytes[..addr_len]);
      bytes.advance(addr_len);
      let port = bytes.get_u16();
      *advance = *advance + 3 + addr_len;
      SocksAddr::Domain(String::from_utf8(domain)?, port)
    }
    _ => {
      return Err(SocksError::InvalidPackageErr(
        InvalidPackageKind::InvalidAddressType(addr_type),
      ));
    }
  };
  return Ok(ParseResult::Complete(addr));
}

fn write_address(buffer: &mut BytesMut, addr: &SocksAddr) {
  buffer.put_u8(addr.addr_type());
  match addr {
    SocksAddr::IPV4(ipv4) => {
      buffer.put_u32(ipv4.ip().to_bits());
      buffer.put_u16(ipv4.port());
    }
    SocksAddr::IPV6(ipv6) => {
      buffer.put_u128(ipv6.ip().to_bits());
      buffer.put_u16(ipv6.port());
    }
    SocksAddr::Domain(domain, port) => {
      let domain = domain.as_bytes();
      buffer.put_u8(domain.len() as u8);
      buffer.put_slice(domain);
      buffer.put_u16(*port);
    }
  }
}

pub(crate) async fn read_package<R: AsyncRead + Unpin, T: SocksPackage>(
  buffer: &mut BytesMut,
  reader: &mut R,
) -> SocksResult<T> {
  loop {
    match T::read(buffer) {
      Ok(ParseResult::Complete(pac)) => {
        trace!("read from TCP: {:?}", pac);
        return Ok(pac);
      }
      Err(err) => {
        return Err(err);
      }
      Ok(ParseResult::Partial) => {
        if buffer.remaining() <= 0 {
          buffer.reserve(buffer.capacity());
        }
        reader.read_buf(buffer).await?;
      }
    }
  }
}

pub(crate) async fn write_package<W: AsyncWrite + Unpin>(
  package: &impl SocksPackage,
  buffer: &mut BytesMut,
  writer: &mut W,
) -> SocksResult<()> {
  trace!("write to TCP: {:?}", package);
  let mut writer = Pin::new(writer);
  package.write(buffer);
  writer.write_all(buffer.as_ref()).await?;
  writer.flush().await?;
  return Ok(buffer.clear());
}

#[derive(Debug)]
pub(crate) struct UdpRequestsPackage {
  fragment: u8,
  addr: SocksAddr,
  data: Bytes
}

impl UdpRequestsPackage {
  pub(crate) fn read(mut buffer: BytesMut) -> SocksResult<UdpRequestsPackage> {
    let mut advance = 0;
    let mut bytes = buffer.as_ref();
    if bytes.remaining() < 4 {
      return Err(SocksError::InvalidPackageErr(InvalidPackageKind::InvalidUdpRequests));
    }
    let rsv = bytes.get_u16();
    if rsv != 0 {
      let rsv = (rsv & 0xFF) as u8 | ((rsv >> 8) & 0xFF) as u8;
      return Err(SocksError::InvalidPackageErr(InvalidPackageKind::InvalidSocks5RsvByte(rsv)));
    }
    advance += 3;
    let fragment = bytes.get_u8();
    let addr = match read_address(&mut bytes, &mut advance) {
      Ok(ParseResult::Complete(addr)) => addr,
      Ok(ParseResult::Partial) => {
        return Err(SocksError::InvalidPackageErr(InvalidPackageKind::InvalidUdpRequests));
      },
      Err(err) => {
        return Err(err);
      }
    };
    buffer.advance(advance);
    let package = UdpRequestsPackage {
      fragment,
      addr,
      data: buffer.freeze()
    };
    return Ok(package);
  }

  pub(crate) fn data_ref(&self) -> &[u8] {
    return self.data.as_ref();
  }

  pub(crate) fn addr_ref(&self) -> &SocksAddr {
    return &self.addr;
  }
}

#[cfg(test)]
mod test {
  use crate::errors::SocksResult;
  use crate::package::{
    read_package, AuthMethodsPackage, AuthSelectPackage, ParseResult,
    PasswordReqPackage, PasswordResPackage, RepliesPackage, RequestsPackage, SocksPackage,
  };
  use crate::{AuthMethod, AuthMethods, RepliesRep, RequestCmd, SocksAddr};
  use bytes::{Buf, BufMut, BytesMut};
  use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

  #[test]
  fn read_auth_methods_package() {
    let data = [0x05, 0x01, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [0x05, 0x02, 0x00, 0x02];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [0x05, 0x01, 0x00, 0x05];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 1);

    let data = [0x05, 0x02, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Partial)));
    assert_eq!(buffer.remaining(), data.len());

    let data = [0x01, 0x00, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));

    let data = [0x05, 0x00, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthMethodsPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));
  }

  #[test]
  fn write_auth_methods_package() {
    let mut buffer = BytesMut::with_capacity(8);
    let mut methods = AuthMethods::new();
    methods.insert(AuthMethod::SKIP);
    let pac = AuthMethodsPackage::new(methods);
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x05, 0x01, 0x00]);

    let mut buffer = BytesMut::with_capacity(8);
    let mut methods = AuthMethods::new();
    methods.insert(AuthMethod::SKIP);
    methods.insert(AuthMethod::PASS);
    let mut pac = AuthMethodsPackage::new(methods);
    pac.write(&mut buffer);
    assert!(
      (buffer.as_ref() == &[0x05, 0x02, 0x00, 0x02])
        || (buffer.as_ref() == &[0x05, 0x02, 0x02, 0x00])
    );
  }

  #[test]
  fn read_auth_select_package() {
    let data = [0x05, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthSelectPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [0x05, 0x00, 0x01];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthSelectPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 1);

    let data = [0x05];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthSelectPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Partial)));

    let data = [0x02, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = AuthSelectPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));
  }

  #[test]
  fn write_auth_select_package() {
    let mut buffer = BytesMut::with_capacity(8);
    let pac = AuthSelectPackage::new(AuthMethod::SKIP);
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x05, 0x00]);

    let mut buffer = BytesMut::with_capacity(8);
    let pac = AuthSelectPackage::new(AuthMethod::PASS);
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x05, 0x02]);
  }

  #[test]
  fn read_password_req_package() {
    let data = [0x01, 0x01, 0x41, 0x01, 0x42];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [0x01, 0x01, 0x41, 0x01, 0x42, 0x01];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 1);

    let data = [0x01, 0x01, 0x41, 0x02, 0x42];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Ok(ParseResult::Partial)));
    assert_eq!(buffer.remaining(), data.len());

    let data = [0x05, 0x01, 0x41, 0x01, 0x42];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));

    let data = [0x01, 0x00, 0x01, 0x42];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));

    let data = [0x05, 0x01, 0x41, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let res = PasswordReqPackage::read(&mut buffer);
    assert!(matches!(res, Err(_)));
  }

  #[test]
  fn write_password_req_package() {
    let mut buffer = BytesMut::with_capacity(8);
    let pac = PasswordReqPackage::new(b"A", b"B");
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x01, 0x01, 0x41, 0x01, 0x42]);

    let mut buffer = BytesMut::with_capacity(8);
    let pac = PasswordReqPackage::new(b"AB", b"B");
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x01, 0x02, 0x41, 0x42, 0x01, 0x42]);
  }

  #[test]
  fn read_password_res_package() {
    let data = [0x01, 0x00];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = PasswordResPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [0x01];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = PasswordResPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Partial)));
    assert_eq!(buffer.remaining(), data.len());
  }

  #[test]
  fn write_password_res_package() {
    let mut buffer = BytesMut::with_capacity(8);
    let pac = PasswordResPackage::new(false);
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x01, 0x01]);

    let mut buffer = BytesMut::with_capacity(8);
    let pac = PasswordResPackage::new(true);
    pac.write(&mut buffer);
    assert_eq!(buffer.as_ref(), &[0x01, 0x00]);
  }

  #[test]
  fn read_requests_package() {
    let data = [0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x0B, 0xB8,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
      0x6d, 0x0B, 0xB8,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8, 0x00,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 1);

    let data = [0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Partial)));
    assert_eq!(buffer.remaining(), data.len());

    let data = [0x05, 0x01, 0x02, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RequestsPackage::read(&mut buffer);
    assert!(matches!(pac, Err(_)));
  }

  #[test]
  fn write_requests_package() {
    let mut buffer = BytesMut::with_capacity(32);
    let ipv4 = SocksAddr::IPV4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
    let pac = RequestsPackage::new(RequestCmd::TCP, ipv4);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8]
    );

    let mut buffer = BytesMut::with_capacity(32);
    let ipv6 = SocksAddr::IPV6(SocketAddrV6::new(
      Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
      3000,
      0,
      0,
    ));
    let pac = RequestsPackage::new(RequestCmd::TCP, ipv6);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[
        0x05, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x0B, 0xB8
      ]
    );

    let mut buffer = BytesMut::with_capacity(32);
    let domain = SocksAddr::Domain("example.com".to_string(), 3000);
    let pac = RequestsPackage::new(RequestCmd::TCP, domain);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[
        0x05, 0x01, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x0B, 0xB8
      ]
    );
  }

  #[test]
  fn read_replies_package() {
    let data = [0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x0B, 0xB8,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
      0x6d, 0x0B, 0xB8,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 0);

    let data = [
      0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8, 0x00,
    ];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Complete(_))));
    assert_eq!(buffer.remaining(), 1);

    let data = [0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    assert!(matches!(pac, Ok(ParseResult::Partial)));
    assert_eq!(buffer.remaining(), data.len());

    let data = [0x05, 0x01, 0x02, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8];
    let mut buffer = BytesMut::from(data.as_ref());
    let pac = RepliesPackage::read(&mut buffer);
    println!("{:?}", pac);
    assert!(matches!(pac, Err(_)));
  }

  #[test]
  fn write_replies_package() {
    let mut buffer = BytesMut::with_capacity(32);
    let ipv4 = SocksAddr::IPV4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
    let pac = RepliesPackage::new(RepliesRep::SUCCESS, ipv4);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[0x05, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x0B, 0xB8]
    );

    let mut buffer = BytesMut::with_capacity(32);
    let ipv6 = SocksAddr::IPV6(SocketAddrV6::new(
      Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
      3000,
      0,
      0,
    ));
    let pac = RepliesPackage::new(RepliesRep::SUCCESS, ipv6);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[
        0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x0B, 0xB8
      ]
    );

    let mut buffer = BytesMut::with_capacity(32);
    let domain = SocksAddr::Domain("example.com".to_string(), 3000);
    let pac = RepliesPackage::new(RepliesRep::SUCCESS, domain);
    pac.write(&mut buffer);
    assert_eq!(
      buffer.as_ref(),
      &[
        0x05, 0x00, 0x00, 0x03, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x0B, 0xB8
      ]
    );
  }

  #[tokio::test]
  async fn read_stream_package() {
    let mut buffer = BytesMut::with_capacity(16);
    let mut stream = tokio_test::io::Builder::new()
      .read(&[0x05, 0x01])
      .read(&[0x00])
      .build();
    let pac = read_package::<_, AuthMethodsPackage>(&mut buffer, &mut stream).await;
    assert!(matches!(pac, Ok(AuthMethodsPackage { .. })));
  }
}
