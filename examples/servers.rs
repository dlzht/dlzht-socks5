#![feature(iter_array_chunks)]

use bytes::Bytes;
use clap::Parser;
use dlzht_socks5::server::SocksServerBuilder;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, error, Level};

#[tokio::main]
async fn main() {
  let param = ServerParam::parse();
  debug!("server build param: {:?}", param);
  let ServerParam {
    addr,
    port,
    allow_auth_skip,
    credentials,
    level,
  } = param;

  tracing_subscriber::fmt().with_max_level(level).init();

  let mut username_password = HashMap::new();
  for [username, password] in credentials.into_iter().array_chunks() {
    username_password.insert(Bytes::from(username), Bytes::from(password));
  }

  let mut builder = SocksServerBuilder::new()
    .allow_auth_skip(allow_auth_skip)
    .tcp_listen_addr(SocketAddr::new(addr, port));
  if !username_password.is_empty() {
    builder = builder.credentials(username_password);
  }

  match builder.build() {
    Ok(server) => match server.start().await {
      Ok(_) => {
        std::process::exit(0);
      }
      Err(err) => {
        error!("server build error: {}", err);
        std::process::exit(1);
      }
    },
    Err(err) => {
      error!("server build error: {}", err);
      std::process::exit(1);
    }
  }
}

#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
struct ServerParam {
  #[arg(short = 'a', long = "addr", default_value = "127.0.0.1")]
  addr: IpAddr,

  #[arg(short = 'p', long = "port", default_value_t = 8080)]
  port: u16,

  #[arg(long = "allow-auth-skip", default_value_t = true)]
  allow_auth_skip: bool,

  #[arg(short = 'c', long = "credential", value_names = ["USERNAME", "PASSWORD"])]
  credentials: Vec<String>,

  #[arg(short = 'l', long = "level", default_value = "warn")]
  level: Level,
}
