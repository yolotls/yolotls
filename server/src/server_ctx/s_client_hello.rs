//! yTLS Server Context ClientHello Processor

use super::TlsServerCtx;
use crate::TlsServerCtxConfig;
use ytls_traits::ClientHelloProcessor;
use ytls_traits::CryptoConfig;
use ytls_traits::CryptoRng;

use ytls_extensions::{ExtAlpnProcessor, TlsExtAlpn};
use ytls_extensions::{ExtCompressCertProcessor, TlsExtCompressCert};
use ytls_extensions::{ExtDelegatedCredentialProcessor, TlsExtDelegatedCredential};
use ytls_extensions::{ExtEncryptedClientHelloProcessor, TlsExtEncryptedClientHello};
use ytls_extensions::{ExtGroupProcessor, TlsExtGroup};
use ytls_extensions::{ExtKeyShareProcessor, TlsExtKeyShare};
use ytls_extensions::{ExtPskeProcessor, PskeKind, TlsExtPske};
use ytls_extensions::{ExtRecSizeLimitProcessor, TlsExtRecSizeLim};
use ytls_extensions::{ExtSigAlgProcessor, TlsExtSigAlg};
use ytls_extensions::{ExtSniProcessor, TlsExtSni};
use ytls_extensions::{ExtVersionProcessor, TlsExtVersion};
use ytls_typed::{TlsCipherSuite, TlsExtension};

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ClientHelloProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> () {
        let ext_t: TlsExtension = ext_id.try_into().unwrap();

        let e_res = match ext_t {
            TlsExtension::ServerNameIndication => TlsExtSni::client_hello_cb(self, ext_data),
            TlsExtension::SupportedGroups => TlsExtGroup::client_group_cb(self, ext_data),
            TlsExtension::KeyShare => TlsExtKeyShare::client_key_share_cb(self, ext_data),
            TlsExtension::SignatureAlgorithms => {
                TlsExtSigAlg::client_signature_algorithm_cb(self, ext_data)
            }
            TlsExtension::SupportedVersions => {
                TlsExtVersion::client_supported_version_cb(self, ext_data)
            }
            TlsExtension::Alpn => TlsExtAlpn::client_alpn_cb(self, ext_data),
            TlsExtension::ExtendedMainSecret => {
                self.extended_main_secret = true;
                Ok(())
            }
            TlsExtension::RecordSizeLimit => {
                TlsExtRecSizeLim::client_rec_size_limit_cb(self, ext_data)
            }
            TlsExtension::EcPointFormats => Ok(()), // d: 0100 (uncompressed always)
            TlsExtension::RenegotiationInfo => Ok(()), // d: 00
            TlsExtension::DelegatedCredential => {
                TlsExtDelegatedCredential::client_delegated_credential_cb(self, ext_data)
            }
            TlsExtension::SessionTicket => Ok(()), // d: -
            TlsExtension::StatusRequest => Ok(()), // d: 0100000000 (RFC 6066 s. 8) OCSP
            TlsExtension::SignedCertificateTimestamp => {
                self.signed_cert_ts = true;
                Ok(())
            }
            TlsExtension::CompressCertificate => {
                TlsExtCompressCert::client_compress_certificate_cb(self, ext_data)
            }
            TlsExtension::PskKeyExchangeModes => TlsExtPske::client_pske_cb(self, ext_data),
            TlsExtension::EncryptedClientHello => {
                TlsExtEncryptedClientHello::client_encrypted_hello_cb(self, ext_data)
            }
            _ => {
                println!(
                    "Missing Handle_extensions ext_id: {} / {:?} - ext_adta: {}",
                    ext_id,
                    ext_t,
                    hex::encode(ext_data)
                );
                Ok(())
            }
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
    #[inline]
    fn handle_client_random(&mut self, cr: &[u8; 32]) -> () {
        let mut r: [u8; 32] = [0; 32];
        r.copy_from_slice(cr);
        self.client_random = Some(r);
    }
    #[inline]
    fn handle_session_id(&mut self, ses_id: &[u8]) -> () {
        let mut s: [u8; 100] = [0; 100];
        if ses_id.len() > 100 {
            return ();
        }
        self.client_session_len = ses_id.len();
        s[0..ses_id.len()].copy_from_slice(ses_id);
        self.client_session_id = Some(s);
    }
}

use ytls_extensions::EntrySniKind;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtSniProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn sni(&mut self, k: EntrySniKind, name: &[u8]) -> bool {
        if k != EntrySniKind::DnsHostname {
            return false;
        }
        // TODO: validate hostname
        let host = match core::str::from_utf8(name) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let r = self.config.dns_host_name(host);
        if r {
            self.downstream_found_host = true;
        }
        r
    }
}

use ytls_typed::Group;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtGroupProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn group(&mut self, group: Group) -> bool {
        if group == Group::X25519 {
            self.group_x25519_supported = true;
            return true;
        }
        false
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtKeyShareProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn key_share(&mut self, g: Group, d: &[u8]) -> bool {
        if g == Group::X25519 {
            let mut pk: [u8; 32] = [0; 32];
            pk.copy_from_slice(d);
            self.client_x25519_pk = Some(pk);
            return true;
        }
        false
    }
}

use ytls_typed::SignatureAlgorithm;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtSigAlgProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn signature_algorithm(&mut self, s_alg: SignatureAlgorithm) -> bool {
        //println!("s_alg = {:?}", s_alg);
        if s_alg == SignatureAlgorithm::RsaPkcs1Sha256 {
            self.sig_alg_rsa_pkcs1_sha256_supported = true;
            return true;
        }
        if s_alg == SignatureAlgorithm::Ed25519 {
            self.sig_alg_ed25519_supported = true;
            return true;
        }
        false
    }
}

use ytls_typed::Version;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtVersionProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn supported_version(&mut self, s_ver: Version) -> bool {
        //println!("Version {:?}", s_ver);
        if s_ver == Version::Tls13 {
            self.tls13_supported = true;
            return true;
        }
        false
    }
}

use ytls_typed::Alpn;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtAlpnProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn alpn<'r>(&mut self, alpn: Alpn<'r>) -> bool {
        self.config.alpn(alpn)
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtRecSizeLimitProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn record_size_limit(&mut self, lim: u16) -> () {
        self.record_size_limit = lim;
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtDelegatedCredentialProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn delegated_credential_signature_algorithm(&mut self, _sa: SignatureAlgorithm) -> bool {
        //println!("Delegated sig alg: {:?}", sa);
        false
    }
}

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtPskeProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn pske_mode(&mut self, _pske: PskeKind) -> () {
        //println!("Pre-Shared Key Exchange Mode: {:?}", pske);
    }
}

use ytls_typed::CertificateCompressKind;

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtCompressCertProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    #[inline]
    fn compress_certificate(&mut self, _alg: CertificateCompressKind) -> () {
        //println!("Certificate Compress avail: {:?}", alg);
    }
}

use ytls_typed::{HaeadKind, HkdfKind};

impl<C: TlsServerCtxConfig, Crypto: CryptoConfig, Rng: CryptoRng> ExtEncryptedClientHelloProcessor
    for TlsServerCtx<C, Crypto, Rng>
{
    fn encrypted_client_hello_outer(
        &mut self,
        config_id: u8,
        kdf: HkdfKind,
        aead: HaeadKind,
        enc: &[u8],
        payload: &[u8],
    ) -> () {
        //println!(
        //    "encrypted_client_hello config_id {} kdf {:?} aead {:?} enc.len {} payload.len {}",
        //    config_id,
        //    kdf,
        //    aead,
        //    enc.len(),
        //    payload.len()
        //);
    }
}
