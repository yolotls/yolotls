// Simple yolotls Server - Record parsing example

use ytls_traits::ClientHelloProcessor;

use std::io::Read;
use std::net::{TcpListener, TcpStream};

struct TlsProcessor {}

// See the IANA registered ext_data / cipher_suite vectors here
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
impl ClientHelloProcessor for TlsProcessor {
    #[inline]
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> () {
        println!(
            "Handle_extensions ext_id: {} ext_adta: {}",
            ext_id,
            hex::encode(ext_data)
        );
    }
    #[inline]
    fn handle_cipher_suite(&mut self, cipher_suite: &[u8; 2]) -> () {
        println!("Handle_cipher_suites: {}", hex::encode(cipher_suite));
    }
    #[inline]
    fn handle_session_id(&mut self, ses_id: &[u8]) {
        println!("Handle_session_id = {}", hex::encode(ses_id));
    }
    #[inline]
    fn handle_client_random(&mut self, client_random: &[u8; 32]) {
        println!("Handle_client_random = {}", hex::encode(client_random));
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buf: [u8; 8192] = [0; 8192];

    let s = stream.read(&mut buf).unwrap();

    println!("Read {s} bytes");
    println!("Bytes = {}", hex::encode(&buf[0..s]));

    let mut yum = TlsProcessor {};

    let hdr = ytls_record::Record::parse_client(&mut yum, &buf[0..s]).unwrap();

    println!("Header = {:?}", hdr);
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
