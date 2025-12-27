// Simple yolotls Server - Record parsing example

use ytls_server::{TlsServerCtx, TlsServerCtxConfig};
use ytls_typed::Alpn;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

struct MyTlsServerCfg;

impl TlsServerCtxConfig for MyTlsServerCfg {
    // Sets the context against a hostname if true
    fn dns_host_name(&self, host: &str) -> bool {
        // We only serve a single hostname
        host == "test.rustcryp.to"
    }
    fn alpn<'r>(&self, alpn: Alpn<'r>) -> bool {
        if alpn == Alpn::Http11 {
            return true;
        }
        false
    }
}

struct Buffers {
    out_buf: Vec<u8>,
}

use ytls_server::TlsLeft;

impl TlsLeft for Buffers {
    fn send_record_out(&mut self, data: &[u8]) -> () {
        self.out_buf.extend_from_slice(data);
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buf: [u8; 8192] = [0; 8192];

    let mut tls_buffers = Buffers {
        out_buf: Vec::with_capacity(8192),
    };

    loop {
        let s = stream.read(&mut buf).unwrap();

        if s == 0 {
            println!("Client disconnected.");
            break;
        }

        println!("Read {s} bytes");
        println!("Bytes = {}", hex::encode(&buf[0..s]));

        let rng = rand::rng();
        
        let crypto_cfg = ytls_rustcrypto::RustCrypto;
        let tls_cfg = MyTlsServerCfg {};
        let mut tls_ctx = TlsServerCtx::with_config_and_crypto(tls_cfg, crypto_cfg, rng).unwrap();
        
        tls_ctx
            .process_tls_records(&mut tls_buffers, &buf[0..s])
            .unwrap();

        println!("Buffer out len = {}", tls_buffers.out_buf.len());

        if tls_buffers.out_buf.len() > 0 {
            stream.write_all(&tls_buffers.out_buf).unwrap();
            tls_buffers.out_buf.clear();
        }
    }
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
