//! google search but through yTLS client

//use ytls_typed::Alpn;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs;

use ytls_client::{TlsClientCtx, TlsClientCtxConfig};

struct MyConfig;

impl TlsClientCtxConfig for MyConfig {
    fn dns_host_name(&self) -> &[u8] {
        b"test.rustcryp.to"
    }
}

use ytls_traits::TlsRight;

struct ApplicationIo {
    in_buf: Vec<u8>,
    out_buf: [u8; 8192],
    out_buf_len: usize,
}

impl Default for ApplicationIo {
    fn default() -> Self {
        Self {
            in_buf: vec![],
            out_buf: [0; 8192],
            out_buf_len: 0,
        }
    }
}

impl TlsRight for ApplicationIo {
    #[inline]
    fn on_decrypted(&mut self, data: &[u8]) -> () {
        self.in_buf.extend_from_slice(data);
    }
    #[inline]
    fn on_encrypt(&self) -> &[u8] {
        &self.out_buf[..self.out_buf_len]
    }
    #[inline]
    fn right_buf_mark_discard_out(&mut self, len: usize) -> () {
        self.out_buf.rotate_left(len);
        self.out_buf_len -= len;
    }
}

struct NetworkIoOut {
    out_buf: Vec<u8>,
}

struct NetworkIoIn {
    in_buf: [u8; 8192],
    in_buf_len: usize,
}

use ytls_client::{TlsLeftIn, TlsLeftOut};

impl TlsLeftOut for NetworkIoOut {
    #[inline]
    fn send_record_out(&mut self, data: &[u8]) -> () {
        self.out_buf.extend_from_slice(data);
    }
}

impl TlsLeftIn for NetworkIoIn {
    #[inline]
    fn left_buf_in(&self) -> &[u8] {
        &self.in_buf[0..self.in_buf_len]
    }
    #[inline]
    fn left_buf_mark_discard_in(&mut self, len: usize) -> () {
        println!("Discarding {len} bytes");
        // This is overly naive & slow, implement proper rotating buffering scheme
        self.in_buf.rotate_left(len);
        self.in_buf_len -= len;
    }
}

fn main() {
    //let mut addrs = "www.google.com:443".to_socket_addrs().unwrap();

    let mut addrs = "test.rustcryp.to:9998".to_socket_addrs().unwrap();

    let addr = addrs.next().unwrap();

    let mut stream = TcpStream::connect(addr).unwrap();

    let mut network_out = NetworkIoOut {
        out_buf: Vec::with_capacity(8192),
    };

    let mut network_in = NetworkIoIn {
        in_buf: [0; 8192],
        in_buf_len: 0,
    };

    let rng = rand::rng();
    let crypto_cfg = ytls_rustcrypto::RustCrypto;

    let tls_cfg = MyConfig {};

    let mut tls_ctx = TlsClientCtx::with_required(tls_cfg, crypto_cfg, rng);
    let mut app_buffers = ApplicationIo::default();

    loop {
        tls_ctx
            .advance_with(&mut network_in, &mut network_out, &mut app_buffers)
            .unwrap();

        println!("Buffer out len = {}", network_out.out_buf.len());

        if network_out.out_buf.len() > 0 {
            stream.write_all(&network_out.out_buf).unwrap();
            network_out.out_buf.clear();
        }

        let b_start = network_in.in_buf_len;
        let b_end = network_in.in_buf.len();
        let s = stream.read(&mut network_in.in_buf[b_start..b_end]).unwrap();

        if s == 0 {
            println!("Client disconnected.");
            break;
        }

        network_in.in_buf_len += s;

        println!("Read {s} bytes");
        println!(
            "Bytes = {}",
            hex::encode(&network_in.in_buf[b_start..b_start + s])
        );
    }
}
