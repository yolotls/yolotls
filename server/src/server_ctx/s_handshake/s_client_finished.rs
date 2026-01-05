//! yTLS Server Context: Client Finished

use crate::{TlsServerCtxConfig, TlsServerCtxError, Rfc8446Error, ServerHandshakeCtx};
use ytls_traits::{CryptoConfig, CryptoRng};
use ytls_traits::CryptoSha256HmacProcessor;

use ytls_record::ClientFinished;

impl<Config, Crypto, Rng> ServerHandshakeCtx<Config, Crypto, Rng>
where
    Config: TlsServerCtxConfig,
    Crypto: CryptoConfig,
    Rng: CryptoRng,
{
    pub(crate) fn check_client_finished<'r>(&self, f: &ClientFinished<'r>) -> Result<(), TlsServerCtxError> {
        let expected_hmac_s = f.hmac();

        // TODO SHA384
        if expected_hmac_s.len() != 32 {
            return Err(TlsServerCtxError::Rfc8446(Rfc8446Error::Unexpected));
        }

        let mut expected_hmac: [u8; 32] = [0; 32];
        expected_hmac.copy_from_slice(expected_hmac_s);

        let hash_finished = match self.hash_finished {
            Some(h) => h,
            None => return Err(TlsServerCtxError::Bug("Hash finished was not guarded for check_client_finished")),
        };

        let hs_key = match self.handshake_finished_client_key {
            Some(ref k) => k,
            None => &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        let mut mac = Crypto::hmac_sha256_init_with_key(hs_key);
        mac.hmac_sha256_update(&hash_finished);
        
        let finished_hmac: [u8; 32] = mac.hmac_sha256_finalize();
        
        use ctutils::{CtEq, Choice};
        let cmp = finished_hmac.ct_ne(&expected_hmac);

        if cmp.to_u8() == 1 {
            return Err(TlsServerCtxError::Rfc8446(Rfc8446Error::Decrypt));
        }
        
        Ok(())
    }
}
