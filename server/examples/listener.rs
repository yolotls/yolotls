// Simple yolotls Server - Record parsing example

use ytls_server::{TlsServerCtx, TlsServerCtxConfig};

use std::io::Read;
use std::net::{TcpListener, TcpStream};

struct MyTlsServerCfg;

impl TlsServerCtxConfig for MyTlsServerCfg {
    // Sets the context against a hostname if true
    fn dns_host_name(&self, host: &str) -> bool {
        // We only serve a single hostname
        host == "test.rustcryp.to"
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buf: [u8; 8192] = [0; 8192];

    let s = stream.read(&mut buf).unwrap();

    println!("Read {s} bytes");
    println!("Bytes = {}", hex::encode(&buf[0..s]));

    let tls_cfg = MyTlsServerCfg {};
    let mut tls_ctx = TlsServerCtx::with_config(tls_cfg).unwrap();

    tls_ctx.process_tls_records(&buf[0..s]).unwrap();
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("192.168.64.3:9999")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        println!("Accepted.");
        handle_client(stream?);
    }
    Ok(())
}
