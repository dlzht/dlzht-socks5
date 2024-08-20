//! error module include all errors occur handling SOCKS5

use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum SocksError {
    /// General io error, e.g. listen, connect
    StdIoError(std::io::Error),

    /// General timeout error, e.g. handshake
    TimeoutErr,

    /// Parse SOCKS5 protocol error
    InvalidPackageErr(InvalidPackageKind),

    /// Invalid auth method, not 0x00 or 0x02
    UnsupportedAuthMethod,

    /// Username/Password auth is not passed
    PasswordAuthNotPassed,

    /// None auth method is supported error
    UnsupportedCommand(u8),

    /// Execute command error
    ExecuteCommandErr(ExecuteCmdKind),

    /// Build SOCKS5 server error
    BuildSocksServerErr(BuildSocksKind),

    /// Build SOCKS5 client error
    BuildSocksClientErr(BuildSocksKind),
}

/// Errors that can occur parsing SOCKS5 protocol.
#[derive(Debug)]
pub enum InvalidPackageKind {
    /// `Version` byte is not 0x05
    InvalidSocks5Version(u8),

    /// None auth method is specified
    InvalidAuthMethodNum(u8),

    /// Duplicated auth method is specified
    DuplicatedAuthMethod(u8),

    /// `Version of the sub negotiation` byte is not 0x01
    InvalidSubNegVersion(u8),

    /// Length of username can not be 0
    InvalidUsernameLength(u8),

    /// Length of password can not be 0
    InvalidPasswordLength(u8),

    /// `RSV` byte is not 0x00
    InvalidSocks5RsvByte(u8),

    /// `ATYP` byte is not IP V4 address(0x01), DOMAINNAME(0x03) or IP V6 address(0x04)
    InvalidAddressType(u8),

    /// `CMD` byte is not CONNECT(0x01), BIND(0x02) or UDP ASSOCIATE(0x03)
    InvalidRequestsCmd(u8),

    /// Domain name is not valid UFT8 string
    InvalidDomainAddress(Vec<u8>),
}

/// Errors of building SOCKS5 client or server
#[derive(Debug)]
pub enum BuildSocksKind {
    /// invalid username, length(byte) of username is 0 or greater than 255
    InvalidUsername,

    /// invalid password, length(byte) of password is 0 or greater than 255
    InvalidPassword,

    /// invalid auth method, neither `NO AUTHENTICATION REQUIRED` nor `USERNAME/PASSWORD` is specified
    InvalidAuthMethod,
}

/// Errors of executing socks5 command
#[derive(Debug)]
pub enum ExecuteCmdKind {
    /// Errors occur in server side, inner error is `std::io::Error`
    Server(std::io::Error),

    /// Errors occur in client side, receiving from server
    Client(u8),
}

impl Display for SocksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{:?}", self);
    }
}

impl std::error::Error for SocksError {}

impl From<std::io::Error> for SocksError {
    fn from(error: std::io::Error) -> Self {
        return SocksError::StdIoError(error);
    }
}

impl From<std::string::FromUtf8Error> for SocksError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        return SocksError::InvalidPackageErr(InvalidPackageKind::InvalidDomainAddress(
            error.into_bytes(),
        ));
    }
}

impl From<tokio::time::error::Elapsed> for SocksError {
    fn from(_value: tokio::time::error::Elapsed) -> Self {
        return SocksError::TimeoutErr;
    }
}

/// Result type often returned from methods that can have socks5 `Error`s.
pub type SocksResult<T> = Result<T, SocksError>;
