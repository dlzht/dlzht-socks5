This library is an implement of SOCKS5, [RFC1928](https://www.rfc-editor.org/rfc/rfc1928). So far, auth method of `NO AUTHENTICATION REQUIRED` and `USERNAME/PASSWORD` is supported, command `CONNECT` is supported.

### Server

#### 1. Run server without any authorization

```rust
use dlzht_socks5::server::SocksServerBuilder;

#[tokio::main]
async fn main() {
    let server = SocksServerBuilder::new()
        .allow_auth_skip(true)
        .build().unwrap();
    let _ = server.start().await;
}
```

#### 2. Run server with password authorization

```rust
use dlzht_socks5::server::SocksServerBuilder;

#[tokio::main]
async fn main() {
    let server = SocksServerBuilder::new()
        .credential(b"username", b"password")
        .build().unwrap();
    let _ = server.start().await;
}
```

#### 3. Run server with handshake timeout

```rust
use std::time::Duration;
use dlzht_socks5::server::SocksServerBuilder;

#[tokio::main]
async fn main() {
    let server = SocksServerBuilder::new()
        .allow_auth_skip(true)
        .handshake_timeout(Duration::from_secs(1))
        .build().unwrap();
    let _ = server.start().await;
}
```

#### 4. Custom validate username/password

```rust
use async_trait::async_trait;
use dlzht_socks5::server::{PasswordAuthority, SocksServerBuilder};

#[tokio::main]
async fn main() {
    let server = SocksServerBuilder::new()
        .custom_auth_pass()
        .build().unwrap();
    let _ = server.start().await;
}

struct DatabaseAuthority {
  database: Database
}

#[async_trait]
impl PasswordAuthority for DatabaseAuthority {
  async fn auth(&self, username: &[u8], password: &[u8]) -> Option<u64> {
    return self.database.select("SELECT id FROM account WHERE username = #{username} AND password = #{password}")
  }
}

struct Database;
impl Database {
  fn select(&self, sql: &str) -> Option<u64> {
    todo!()
  }
}
```
### Client

#### 1. Run client without any authorization

```rust
use dlzht_socks5::client::SocksClientBuilder;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[tokio::main]
async fn main() {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut client = SocksClientBuilder::new()
        .server_address(address)
        .allow_auth_skip(true)
        .build()
        .unwrap();
    let mut stream = client
        .connect(("127.0.0.1".to_string(), 9000))
        .await
        .unwrap();
}
```

#### 2. Run client with password authorization

```rust
use dlzht_socks5::client::SocksClientBuilder;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[tokio::main]
async fn main() {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut client = SocksClientBuilder::new()
        .server_address(address)
        .credential(b"username", b"password")
        .build()
        .unwrap();
    let mut stream = client
        .connect(("127.0.0.1".to_string(), 9000))
        .await
        .unwrap();
}
```

#### 3. Run client with handshake timeout

```rust
use dlzht_socks5::client::SocksClientBuilder;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[tokio::main]
async fn main() {
    use std::time::Duration;
let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut client = SocksClientBuilder::new()
        .server_address(address)
        .allow_auth_skip(true)
        .handshake_timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let mut stream = client
        .connect(("127.0.0.1".to_string(), 9000))
        .await
        .unwrap();
}
```
Default handshake timeout is 10 minutes, which almost means no timeout configured.
