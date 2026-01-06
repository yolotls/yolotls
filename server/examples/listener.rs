// Simple yolotls Server - Record parsing example

use ytls_server::{TlsServerCtx, TlsServerCtxConfig};
use ytls_typed::Alpn;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

struct MyTlsServerCfg {
    ca_cert: Vec<u8>,
    server_cert: Vec<u8>,
    server_private_key: Vec<u8>,
}

impl TlsServerCtxConfig for MyTlsServerCfg {
    // Sets the context against a hostname if true
    #[inline]
    fn dns_host_name(&self, host: &str) -> bool {
        // We only serve a single hostname
        host == "test.rustcryp.to"
    }
    #[inline]
    fn alpn<'r>(&self, alpn: Alpn<'r>) -> bool {
        if alpn == Alpn::Http11 {
            return true;
        }
        false
    }
    #[inline]
    fn server_private_key(&self) -> &[u8] {
        &self.server_private_key
    }
    #[inline]
    fn server_cert_chain(&self) -> &[u8] {
        &[0, 1]
    }
    #[inline]
    fn server_cert(&self, id: u8) -> &[u8] {
        match id {
            0 => &self.server_cert,
            1 => &self.ca_cert,
            _ => unreachable!(),
        }
    }
}

use ytls_traits::TlsRight;

struct ApplicationIo {}

impl TlsRight for ApplicationIo {}

struct NetworkIoOut {
    out_buf: Vec<u8>,
}

struct NetworkIoIn {
    in_buf: [u8; 8192],
    in_buf_len: usize,
}

use ytls_server::{TlsLeftIn, TlsLeftOut};

impl TlsLeftOut for NetworkIoOut {
    fn send_record_out(&mut self, data: &[u8]) -> () {
        self.out_buf.extend_from_slice(data);
    }
}

impl TlsLeftIn for NetworkIoIn {
    /*
        fn left_bufs_mut(&mut self) -> (mut &[u8], &mut [u8]) {
            (&self.in_buf[0..self.in_buf_len], &self,out_buf[self.out_buf_len..])
        }
        fn left_buf_mark_send_out(&mut self, len: usize) -> () {
            println!("Sending out {len} bytes");
            self.out_buf_len += len;
    }*/
    fn left_buf_in(&self) -> &[u8] {
        &self.in_buf[0..self.in_buf_len]
    }
    fn left_buf_mark_discard_in(&mut self, len: usize) -> () {
        println!("Discarding {len} bytes");
        // This is overly naive & slow, implement proper rotating buffering scheme
        self.in_buf.rotate_left(len);
        self.in_buf_len -= len;
    }
}

//const CA: &'static str = "test_certs/ca.rsa4096.crt";
//const CA: &'static str = "test_certs/ca.ed25519.crt";
const CA: &'static str = "../test_certs/ca.prime256v1.crt";

//const CERT: &'static str = "test_certs/rustcryp.to.rsa4096.ca_signed.crt";
//const CERT: &'static str = "test_certs/rustcryp.to.ed25519.ca_signed.crt";
const CERT: &'static str = "../test_certs/rustcryp.to.prime256v1.ca_signed.crt";

//const KEY: &'static str = "test_certs/rustcryp.to.rsa4096.key";
//const KEY: &'static str = "test_certs/rustcryp.to.ed25519.key";
const KEY: &'static str = "../test_certs/rustcryp.to.prime256v1.pem";

fn load_pem_vec(path: &str) -> Vec<u8> {
    let mut f = std::fs::File::open(path).unwrap();
    let mut data: Vec<u8> = vec![];
    f.read_to_end(&mut data).unwrap();
    data
}

fn handle_client(mut stream: TcpStream) {
    //let mut buf: [u8; 8192] = [0; 8192];

    let mut network_out = NetworkIoOut {
        out_buf: Vec::with_capacity(8192),
    };

    let mut network_in = NetworkIoIn {
        in_buf: [0; 8192],
        in_buf_len: 0,
    };

    let mut app_buffers = ApplicationIo {};

    let rng = rand::rng();
    let crypto_cfg = ytls_rustcrypto::RustCrypto;

    let ca_vec = load_pem_vec(CA);
    let cert_vec = load_pem_vec(CERT);
    let key_vec = load_pem_vec(KEY);

    let (cert_type_label, cert_data) = pem_rfc7468::decode_vec(&cert_vec).unwrap();
    println!(
        "Loaded Cert<{:?}> Len<{}>",
        cert_type_label,
        cert_data.len()
    );

    let (key_type_label, key_data_der) = pem_rfc7468::decode_vec(&key_vec).unwrap();
    println!(
        "Loaded Private Key<{:?}> DER Len<{}>",
        key_type_label,
        key_data_der.len()
    );

    use sec1::EcPrivateKey;

    let key_info = EcPrivateKey::try_from(key_data_der.as_ref()).unwrap();
    println!("private_key length = {}", key_info.private_key.len());
    let key_data = key_info.private_key.to_vec();

    println!("Public Key: {}", hex::encode(key_info.public_key.unwrap()));

    let (ca_type_label, ca_data) = pem_rfc7468::decode_vec(&ca_vec).unwrap();
    println!("Loaded CA<{:?}> Len<{}>", ca_type_label, ca_data.len());

    let tls_cfg = MyTlsServerCfg {
        ca_cert: ca_data,
        server_cert: cert_data,
        server_private_key: key_data,
    };

    let mut tls_ctx = TlsServerCtx::with_required(tls_cfg, crypto_cfg, rng);
    //let mut tls_ctx = TlsServerCtx::with_config_and_crypto(tls_cfg, crypto_cfg, rng).unwrap();

    loop {
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

        // &buf[0..s]
        tls_ctx
            .advance_with(&mut network_in, &mut network_out, &mut app_buffers)
            .unwrap();

        println!("Buffer out len = {}", network_out.out_buf.len());

        if network_out.out_buf.len() > 0 {
            stream.write_all(&network_out.out_buf).unwrap();
            network_out.out_buf.clear();
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
