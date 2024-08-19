This library is an implement of SOCKS5, [RFC1928](https://www.rfc-editor.org/rfc/rfc1928). So far, auth method of `NO AUTHENTICATION REQUIRED` and `USERNAME/PASSWORD` is supported, command `CONNECT` is supported.

### Examples

#### Run server without any authorization

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

#### Run server with password authorization

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

#### Custom validate username/password

Will support soon

#### Run client without any authorization

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

#### Run client with password authorization

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