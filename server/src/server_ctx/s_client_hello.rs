//! yTLS Server Context ClientHello Processor

use super::TlsServerCtx;
use ytls_traits::HelloProcessor;

use ytls_extensions::{ExtSniProcessor, TlsExtSni};
use ytls_typed::TlsExtension;

impl HelloProcessor for TlsServerCtx {
    #[inline]
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> () {
        let ext_t: TlsExtension = ext_id.try_into().unwrap();
        println!(
            "Handle_extensions ext_id: {} / {:?} - ext_adta: {}",
            ext_id,
            ext_t,
            hex::encode(ext_data)
        );

        let e_res = match ext_t {
            TlsExtension::ServerNameIndication => TlsExtSni::client_hello_cb(self, ext_data),
            _ => Ok(()),
        };

        match e_res {
            Err(e) => println!("- Error: {:?}", e),
            Ok(_) => {}
        }
    }
    #[inline]
    fn handle_cipher_suite(&mut self, cipher_suite: &[u8]) -> () {
        println!("Handle_cipher_suites: {}", hex::encode(cipher_suite));
    }
}

use ytls_extensions::EntrySniKind;

impl ExtSniProcessor for TlsServerCtx {
    #[inline]
    fn sni(&mut self, k: EntrySniKind, name: &[u8]) -> bool {
        println!(
            "SNI: {} - {:?}",
            core::str::from_utf8(name).unwrap(),
            hex::encode(name)
        );
        todo!();
        true
    }
}
