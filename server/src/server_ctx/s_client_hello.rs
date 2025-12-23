//! yTLS Server Context ClientHello Processor

use super::TlsServerCtx;
use crate::TlsServerCtxConfig;
use ytls_traits::HelloProcessor;

use ytls_extensions::{ExtSniProcessor, TlsExtSni};
use ytls_extensions::{ExtGroupProcessor, TlsExtGroup};
use ytls_extensions::{ExtKeyShareProcessor, TlsExtKeyShare};
use ytls_extensions::{ExtSigAlgProcessor, TlsExtSigAlg};
use ytls_extensions::{ExtVersionProcessor, TlsExtVersion};
use ytls_typed::{TlsExtension, TlsCipherSuite};

impl<C: TlsServerCtxConfig> HelloProcessor for TlsServerCtx<C> {
    #[inline]
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> () {
        let ext_t: TlsExtension = ext_id.try_into().unwrap();


        let e_res = match ext_t {
            TlsExtension::ServerNameIndication => TlsExtSni::client_hello_cb(self, ext_data),
            TlsExtension::SupportedGroups => TlsExtGroup::client_group_cb(self, ext_data),
            TlsExtension::KeyShare => TlsExtKeyShare::client_key_share_cb(self, ext_data),
            TlsExtension::SignatureAlgorithms => TlsExtSigAlg::client_signature_algorithm_cb(self, ext_data),
            TlsExtension::SupportedVersions => TlsExtVersion::client_supported_version_cb(self, ext_data),
            _ => {
                println!(
                    "Missing Handle_extensions ext_id: {} / {:?} - ext_adta: {}",
                    ext_id,
                    ext_t,
                    hex::encode(ext_data)
                );                
                Ok(())
            },
        };

        match e_res {
            Err(e) => println!("- Error: {:?}", e),
            Ok(_) => {}
        }
    }
    #[inline]
    fn handle_cipher_suite(&mut self, cipher_suite: &[u8; 2]) -> () {
        let t_suite: TlsCipherSuite = cipher_suite.into();
        if t_suite == TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256 {
            self.chacha20_poly1305_sha256_supported = true
        }
    }
}

use ytls_extensions::EntrySniKind;

impl<C: TlsServerCtxConfig> ExtSniProcessor for TlsServerCtx<C> {
    #[inline]
    fn sni(&mut self, k: EntrySniKind, name: &[u8]) -> bool {
        // TODO: validate hostname
        let host = match core::str::from_utf8(name) {
            Ok(h) => h,
            Err(_) => return false,
        };
        self.config.dns_host_name(host)
    }
}

use ytls_typed::Group;

impl<C: TlsServerCtxConfig> ExtGroupProcessor for TlsServerCtx<C> {
    #[inline]
    fn group(&mut self, group: Group) -> bool {
        if group == Group::X25519 {
            self.group_x25519_supported = true;
            return true;
        }
        false
    }
}

impl<C: TlsServerCtxConfig> ExtKeyShareProcessor for TlsServerCtx<C> {
    #[inline]
    fn key_share(&mut self, g: Group, d: &[u8]) -> bool {
        //println!("Client_hello_key_share = g: {:?} d.len {}", g, d.len());
        true
    }
}

use ytls_typed::SignatureAlgorithm;

impl<C: TlsServerCtxConfig> ExtSigAlgProcessor for TlsServerCtx<C> {
    #[inline]
    fn signature_algorithm(&mut self, s_alg: SignatureAlgorithm) -> bool {
        if s_alg == SignatureAlgorithm::Ed25519 {
            return true;
        }
        false
    }
}

use ytls_typed::Version;

impl<C: TlsServerCtxConfig> ExtVersionProcessor for TlsServerCtx<C> {
    #[inline]
    fn supported_version(&mut self, s_ver: Version) -> bool {
        if s_ver == Version::Tls13 {
            self.tls13_supported = true;
            return true;
        }
        false
    }
}
