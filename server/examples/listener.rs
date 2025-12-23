// Simple yolotls Server - Record parsing example

use ytls_server::{TlsServerCtx, TlsServerCtxConfig};

use std::net::{TcpListener, TcpStream};
use std::io::Read;

fn handle_client(mut stream: TcpStream) {

    let mut buf: [u8; 8192] = [0; 8192];
    
    let s = stream.read(&mut buf).unwrap();

    println!("Read {s} bytes");
    println!("Bytes = {}", hex::encode(&buf[0..s]));

    let tls_cfg = TlsServerCtxConfig {};
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
