//! Static Record Builder

use crate::error::BuilderError;
use crate::RecordBuffer;
use crate::WrappedRecordBuffer;

use ytls_traits::EncryptedExtensionsBuilder;
use ytls_traits::HandshakeBuilder;
use ytls_traits::ServerCertificatesBuilder;
use ytls_traits::ServerHelloBuilder;
use ytls_traits::WrappedHandshakeBuilder;

/// Provides statically allocated Record Builder based on worst case
/// estimation of the maximum size of record.
/// Typically record sizes need to be also limited based on the record
/// limit extension but this has to be done in runtime.
#[derive(Debug, PartialEq)]
pub struct StaticRecordBuilder<const N: usize> {
    rec_buf: RecordBuffer<N>,
}

/// Same as [`StaticRecordBuilder`] but provides wrapping into TLS1.2 AppData
/// which is typically used when the records are AEAD'd to preserve compatibility
/// with the middleboxes.
#[derive(Debug, PartialEq)]
pub struct WrappedStaticRecordBuilder<const N: usize> {
    rec_buf: WrappedRecordBuffer<N>,
}

impl<const N: usize> WrappedHandshakeBuilder for WrappedStaticRecordBuilder<N> {
    type Error = BuilderError;
    /// Construct handshake server certificate/s.
    fn server_certificates<S: ServerCertificatesBuilder>(s: &S) -> Result<Self, Self::Error> {
        Ok(Self {
            rec_buf: WrappedRecordBuffer::<N>::ServerCertificates(
                super::b_dhs_server_certificate::BufStaticServerCertificates::<N>::static_from_untyped(s)?,
            ),
        })
    }
    /// Construct handshake encrypted extensions.
    fn encrypted_extensions<S: EncryptedExtensionsBuilder>(s: &S) -> Result<Self, Self::Error> {
        Ok(Self {
            rec_buf: WrappedRecordBuffer::<N>::EncryptedExtensions(
                super::b_dhs_encrypted_extensions::BufStaticEncryptedExtensions::<N>::static_from_untyped(s)?,
            ),
        })
    }
    #[inline]
    fn as_disjoint_mut_for_aead(&mut self) -> Result<[&mut [u8]; 2], Self::Error> {
        match self.rec_buf {
            WrappedRecordBuffer::ServerCertificates(ref mut s) => s.as_disjoint_mut_for_aead(),
            WrappedRecordBuffer::EncryptedExtensions(ref mut s) => s.as_disjoint_mut_for_aead(),
        }
    }
    #[inline]
    fn set_auth_tag(&mut self, new_tag: &[u8; 16]) {
        match self.rec_buf {
            WrappedRecordBuffer::ServerCertificates(ref mut s) => s.set_auth_tag(new_tag),
            WrappedRecordBuffer::EncryptedExtensions(ref mut s) => s.set_auth_tag(new_tag),
        }
    }
    #[inline]
    fn as_ciphertext_mut(&mut self) -> &mut [u8] {
        match self.rec_buf {
            WrappedRecordBuffer::ServerCertificates(ref mut s) => s.as_ciphertext_mut(),
            WrappedRecordBuffer::EncryptedExtensions(ref mut s) => s.as_ciphertext_mut(),
        }
    }
    #[inline]
    fn as_hashing_context_ref(&self) -> &[u8] {
        match self.rec_buf {
            WrappedRecordBuffer::ServerCertificates(ref s) => &s.as_hashing_context_ref(),
            WrappedRecordBuffer::EncryptedExtensions(ref s) => &s.as_hashing_context_ref(),
        }
    }
    #[inline]
    fn as_encoded_bytes(&self) -> &[u8] {
        match self.rec_buf {
            WrappedRecordBuffer::ServerCertificates(ref s) => &s.as_encoded_bytes(),
            WrappedRecordBuffer::EncryptedExtensions(ref s) => &s.as_encoded_bytes(),
        }
    }
}

impl<const N: usize> HandshakeBuilder for StaticRecordBuilder<N> {
    type Error = BuilderError;
    /// Construct a Handshake record featuring a Server Hello from untyped raw data.
    #[inline]
    fn server_hello_untyped<S: ServerHelloBuilder>(s: &S) -> Result<Self, Self::Error> {
        Ok(Self {
            rec_buf: RecordBuffer::<N>::ServerHello(super::b_server_hello::BufStaticServerHello::<
                N,
            >::static_from_untyped(s)?),
        })
    }
    #[inline]
    fn as_hashing_context(&self) -> &[u8] {
        match self.rec_buf {
            RecordBuffer::ServerHello(ref h) => &h.as_hashing_context(),
        }
    }
    #[inline]
    fn as_encoded_bytes(&self) -> &[u8] {
        match self.rec_buf {
            RecordBuffer::ServerHello(ref h) => &h.as_encoded_bytes(),
        }
    }
}
