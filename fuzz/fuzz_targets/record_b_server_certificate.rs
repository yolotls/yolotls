#![no_main]
use libfuzzer_sys::{fuzz_target, Corpus};
use ytls_record::Record;
use ytls_traits::ServerCertificatesBuilder;

struct Tester<'r> {
    d: &'r [u8],
}

impl<'r> ServerCertificatesBuilder for Tester<'r> {
    #[inline]
    fn server_certs_list(&self) -> &[u8] {
        &[0]
    }
    #[inline]
    fn server_cert_data(&self, id: u8) -> &[u8] {
        self.d
    }
    #[inline]
    fn server_cert_extensions(&self, id: u8) -> &[u8] {
        &[]
    }
}

use ytls_record::WrappedStaticRecordBuilder;
use ytls_traits::WrappedHandshakeBuilder;

fuzz_target!(|data: &[u8]| -> Corpus {

    if data.len() > 8000 {
        return Corpus::Reject;
    }
    
    let tester = Tester { d: data };
    
    match WrappedStaticRecordBuilder::<8192>::server_certificates(&tester) {
        Ok(_) => {},
        Err(_) => {},
    }

    Corpus::Keep
});
    
