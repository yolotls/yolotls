//! yTLS Server Application Ctx

use crate::{CtxError, Rfc8446Error};
use ytls_traits::CtxApplicationProcessor;
use ytls_traits::ShutdownComplete;
use ytls_traits::{TlsLeftIn, TlsLeftOut, TlsRight};

use ytls_traits::CryptoConfig;
use ytls_traits::SecretStore;

use ytls_record::Content;
use ytls_record::Record;
use ytls_util::Nonce12;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// yTLS Server Application Ctx
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct ServerApplicationCtx<Crypto> {
    //crypto: Crypto,
    application_server_key: [u8; 32],
    application_client_key: [u8; 32],
    application_server_iv: Nonce12,
    application_client_iv: Nonce12,
    _pt: core::marker::PhantomData<Crypto>,
}

impl<Crypto> ServerApplicationCtx<Crypto>
where
    Crypto: CryptoConfig,
{
    pub fn with_required<S: SecretStore>(_crypto: Crypto, s: &S) -> Self {
        let mut application_server_key: [u8; 32] = [0; 32];
        let mut application_client_key: [u8; 32] = [0; 32];
        let mut application_server_iv_raw: [u8; 12] = [0; 12];
        let mut application_client_iv_raw: [u8; 12] = [0; 12];

        application_server_key.copy_from_slice(s.load_ap_server_key());
        application_client_key.copy_from_slice(s.load_ap_client_key());
        application_server_iv_raw.copy_from_slice(s.load_ap_server_iv());
        application_client_iv_raw.copy_from_slice(s.load_ap_client_iv());

        let application_server_iv = Nonce12::from_ks_iv(&application_server_iv_raw);
        let application_client_iv = Nonce12::from_ks_iv(&application_client_iv_raw);

        Self {
            _pt: core::marker::PhantomData,
            application_server_key,
            application_client_key,
            application_server_iv,
            application_client_iv,
        }
    }
}

impl<Crypto> CtxApplicationProcessor for ServerApplicationCtx<Crypto>
where
    Crypto: CryptoConfig,
{
    type Error = CtxError;

    fn spin_application<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(
        &mut self,
        li: &mut Li,
        lo: &mut Lo,
        right: &mut R,
    ) -> Result<Option<ShutdownComplete>, Self::Error> {
        let init_data = li.left_buf_in();
        let init_len = init_data.len();
        let mut data = init_data;

        if init_len == 0 {
            return Ok(None);
        }

        #[allow(unused_assignments)]
        let mut consumed = 0;

        loop {
            let (rec, remaining) =
                Record::parse_client_appdata(data).map_err(|e| CtxError::Record(e))?;

            consumed = init_len - remaining.len();

            if let Content::ApplicationData = rec.content() {
                let key = self.application_client_key;
                let nonce: [u8; 12] = match self.application_client_iv.use_and_incr() {
                    Some(cur) => cur,
                    None => return Err(CtxError::ExhaustedIv),
                };

                let cipher = Crypto::aead_chaha20poly1305(&key);
                let full_payload = rec.as_bytes();
                let full_payload_len = full_payload.len();
                let mut tag: [u8; 16] = [0; 16];

                let body_len = full_payload_len - 16;
                let mut body: [u8; 8192] = [0; 8192];
                body[0..body_len].copy_from_slice(&full_payload[0..body_len]);
                tag.copy_from_slice(&full_payload[body_len..body_len + 16]);
                let additional_data = rec.header_as_bytes();
                use ytls_traits::CryptoChaCha20Poly1305Processor;
                cipher
                    .decrypt_in_place(&nonce, &additional_data, &mut body[0..body_len], &tag)
                    .map_err(|_| CtxError::Rfc8446(Rfc8446Error::Decrypt))?;

                right.on_decrypted(&body[0..body_len - 1]);

                let d = right.on_encrypt();

                if d.len() > 0 {
                    let server_key = self.application_server_key;
                    let server_nonce: [u8; 12] = match self.application_server_iv.use_and_incr() {
                        Some(cur) => cur,
                        None => return Err(CtxError::ExhaustedIv),
                    };

                    use ytls_record::WrappedAppStaticRecordBuilder;
                    use ytls_traits::WrappedApplicationBuilder;

                    let mut record_encrypt =
                        WrappedAppStaticRecordBuilder::<8192>::application_data(d)
                            .map_err(CtxError::Builder)?;

                    let cipher = Crypto::aead_chaha20poly1305(&server_key);

                    // TODO: transcript
                    let tag = if let Ok([additional_data, encrypt_payload]) =
                        record_encrypt.as_disjoint_mut_for_aead()
                    {
                        cipher
                            .encrypt_in_place(
                                &server_nonce,
                                &additional_data,
                                encrypt_payload.as_mut(),
                            )
                            .map_err(|_| CtxError::Bug("Encrypt failure."))?
                    } else {
                        return Err(CtxError::Bug(
                            "Disjoint for AEAD failed at Application data.",
                        ));
                    };
                    record_encrypt.set_auth_tag(&tag);

                    lo.send_record_out(record_encrypt.as_encoded_bytes());
                }
            }

            if remaining.len() == 0 {
                break;
            }

            data = remaining;
        }
        li.left_buf_mark_discard_in(consumed);

        Ok(None)
    }
}
