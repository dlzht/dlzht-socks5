// use bytes::BytesMut;
use bytes::BytesMut;
use dlzht_socks5::client::SocksClientBuilder;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    let mut client = SocksClientBuilder::new()
        .server_address(address)
        .allow_auth_skip(true)
        .credential(b"username", b"password")
        .build()
        .unwrap();
    let mut stream = client
        .connect(("127.0.0.1".to_string(), 9000))
        .await
        .unwrap();

    let request = b"GET /rainbow HTTP/1.1\r\n\
        Accept: */*\r\n\
        Accept-Encoding: gzip, deflate, br\r\n\
        Connection: keep-alive\r\n\
        Host: 127.0.0.1:9000\r\n\
        User-Agent: xh/0.22.2\r\n\r\n";
    let _ = stream.write_all(request).await;
    let _ = stream.flush().await;
    let mut buffer = BytesMut::with_capacity(1024);
    let _ = stream.read_buf(&mut buffer).await;
}
