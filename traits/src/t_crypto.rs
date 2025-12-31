//! ytls Crypto traits

//----------------------------------------------------------
// Providers
//----------------------------------------------------------

#[doc(inline)]
pub use rand_core::CryptoRng;

/// Cryptography configuration is provied through implmenting
/// this trait. Typically providers provide implementation or
/// implementer can provide a mix of used primitives.
pub trait CryptoConfig {
    type PrkError;
    /// AEAD ChaCha20Poly1305 with Key and Nonce / IV
    fn aead_chaha20poly1305(_key: &[u8; 32]) -> impl CryptoChaCha20Poly1305Processor;
    /// Hkdf256 Sha256 from strong pre-existing prk
    fn hkdf_sha256_from_prk(
        _prk: &[u8],
    ) -> Result<impl CryptoSha256HkdfGenProcessor, Self::PrkError>;
    /// Provide the configured Hkdf Sha256 impl
    fn hkdf_sha256_init() -> impl CryptoSha256HkdfExtractProcessor;
    /// Provide the configured SHA256 Hasher impl
    fn sha256_init() -> impl CryptoSha256TranscriptProcessor;
    /// Provide the configured SHA384 Hasher impl
    fn sha384_init() -> impl CryptoSha384TranscriptProcessor;
    /// Provide the configured Ephemeral X25519 impl
    fn x25519_init<R: CryptoRng>(&mut self, _: &mut R) -> impl CryptoX25519Processor;
}

/// HKDF (Hashing Key Derivation Function) Extract Processor
pub trait CryptoSha256HkdfExtractProcessor {
    /// HKDF Using SHA256
    fn hkdf_sha256_extract(
        &self,
        _salt: Option<&[u8]>,
        _ikm: &[u8],
    ) -> ([u8; 32], impl CryptoSha256HkdfGenProcessor);
}

/// HKDF Gen Processor, e.g. to Expand
pub trait CryptoSha256HkdfGenProcessor {
    /// Associated error
    type Error;
    /// HKDF Using SHA256.
    fn hkdf_sha256_expand(&self, _info: &[u8], _okm: &mut [u8]) -> Result<(), Self::Error>;
}

/// X25519 processor used to calculate the shared secret with
/// the given input public key and returning the shared secret.
pub trait CryptoX25519Processor {
    /// Provide the associated public key
    fn x25519_public_key(&self) -> [u8; 32];
    /// Typically performns Diffie Hellman with the given public key
    fn x25519_shared_secret(self, _pub_key: &[u8; 32]) -> [u8; 32];
}

/// Transcript processor used to hash handshakes.
/// Typically implemented by the crypto provider.
pub trait CryptoSha256TranscriptProcessor {
    /// Update the SHA256 Transcript with the given data
    fn sha256_update(&mut self, _: &[u8]) -> ();
    /// Finalize the current SHA384 digest
    fn sha256_finalize(self) -> [u8; 32];
}

/// Transcript processor used to hash handshakes.
/// Typically implemented by the crypto provider.
pub trait CryptoSha384TranscriptProcessor {
    /// Update the SHA384 Transcript with the given data
    fn sha384_update(&mut self, _: &[u8]) -> ();
    /// Finalize the current SHA384 digest
    fn sha384_finalize(self) -> [u8; 48];
}

#[derive(Debug)]
pub enum AeadError {
    Opaque,
}

/// ChaCha20Poly1305 AEAD Processor
pub trait CryptoChaCha20Poly1305Processor {
    fn encrypt_in_place(
        &self,
        _nonce: &[u8; 12],
        _additional_data: &[u8],
        _to_encrypt: &mut [u8],
    ) -> Result<[u8; 16], AeadError>;
}
