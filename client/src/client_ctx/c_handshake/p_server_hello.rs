//! yTLS Server Hello Processor

use crate::ClientHandshakeCtx;
use crate::TlsClientCtxConfig;
use ytls_traits::{CryptoConfig, CryptoRng};

use ytls_traits::ServerHelloProcessor;
use ytls_traits::ServerRecordProcessor;
use ytls_typed::{TlsCipherSuite, TlsExtension};

use ytls_extensions::{ExtKeyShareProcessor, TlsExtKeyShare};
use ytls_typed::Group;

#[derive(Default)]
pub(crate) struct ServerHello {
    pub(crate) pk_x25519: Option<[u8; 32]>,
}

impl ExtKeyShareProcessor for ServerHello {
    #[inline]
    fn key_share(&mut self, g: Group, d: &[u8]) -> bool {
        if g == Group::X25519 {
            let mut pk: [u8; 32] = [0; 32];
            pk.copy_from_slice(d);
            self.pk_x25519 = Some(pk);
            return true;
        }
        false
    }
}

#[derive(Default)]
pub(crate) struct ServerRecord {
    pub(crate) server_hello: ServerHello,
}

impl ServerRecordProcessor for ServerRecord {
    type ServerHelloHandler = ServerHello;

    fn server_hello(&mut self) -> &mut Self::ServerHelloHandler {
        &mut self.server_hello
    }
}

impl ServerHelloProcessor for ServerHello {
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> () {
        //println!("Extension {} data {}", ext_id, hex::encode(ext_data));

        let ext_t: TlsExtension = match ext_id.try_into() {
            Ok(ext_t) => ext_t,
            Err(_) => {
                //println!("Unmapped unknown extension u16 {} data: {}", ext_id, hex::encode(ext_data));
                return ();
            }
        };

        match ext_t {
            TlsExtension::KeyShare => match TlsExtKeyShare::server_key_share_cb(self, ext_data) {
                Ok(_) => {}
                Err(_) => {}
            },
            TlsExtension::SupportedVersions => {
                // 0304
                // println!("Server picked up version {}", hex::encode(ext_data));
            }
            _ => {
                //println!("Need to handle extension {:?} data: {}", ext_t, hex::encode(ext_data));
            }
        }
    }
    fn handle_session_id(&mut self, _ses_id: &[u8]) -> () {
        // todo
    }
    fn handle_selected_cipher_suite(&mut self, _cipher_suite: [u8; 2]) -> () {
        //println!("Cipher suite selected: {}", hex::encode(cipher_suite));
    }
    fn handle_server_random(&mut self, _sr: &[u8; 32]) -> () {
        //println!("Server random: {}", hex::encode(_sr));
    }
}
