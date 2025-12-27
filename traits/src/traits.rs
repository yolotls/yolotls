//! ytls traits

//use ytls_util::ByteSlices;

//----------------------------------------------------------
// Providers
//----------------------------------------------------------

#[doc(inline)]
pub use rand_core::CryptoRng;

/// Cryptography configuration is provied through implmenting
/// this trait. Typically providers provide implementation or
/// implementer can provide a mix of used primitives.
pub trait CryptoConfig {
    // Provide the configured Hkdf Sha256 impl
    //fn hkdf_sha256_init() -> impl CryptoSha256HkdfProcessor;    
    /// Provide the configured SHA256 Hasher impl
    fn sha256_init() -> impl CryptoSha256TranscriptProcessor;   
    /// Provide the configured SHA384 Hasher impl
    fn sha384_init() -> impl CryptoSha384TranscriptProcessor;
    /// Provide the configured Ephemeral X25519 impl
    fn x25519_init<R: CryptoRng>(&mut self, _: &mut R) -> impl CryptoX25519Processor;
}

/// Hkdf
pub trait CryptoSha256HkdfProcessor {
    
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

//----------------------------------------------------------
// SendOut is required for I/O layer linkage
//----------------------------------------------------------

/// TLS State Machine Left (Ciphertext) or "Network" I/O side
pub trait TlsLeft {
    /// Send encoded record data out.
    fn send_record_out(&mut self, data: &[u8]) -> ();
}

//----------------------------------------------------------
// Record Parsing
//----------------------------------------------------------

pub trait ClientHelloProcessor {
    fn handle_extension(&mut self, _ext_id: u16, _ext_data: &[u8]) -> ();
    fn handle_cipher_suite(&mut self, _cs: &[u8; 2]) -> ();
    fn handle_client_random(&mut self, _cr: &[u8; 32]) -> ();
    fn handle_session_id(&mut self, _ses_id: &[u8]) -> ();
}

//----------------------------------------------------------
// Record Building (Untyped)
//----------------------------------------------------------

/// Non-typed Handshake Builder with raw data inputs.
/// This is implemented by the [`ytls_record::Record`] where as
/// the required inputs are through the client/server contextes.
pub trait UntypedHandshakeBuilder {
    type Error;
    /// Build ServerHello with untyped inputs
    fn server_hello_untyped<S: UntypedServerHelloBuilder>(_: &S) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Provide the raw encoded bytes but without header
    fn without_header_as_bytes(&self) -> &[u8];
    /// Provide the raw encoded bytes
    fn as_encoded_bytes(&self) -> &[u8];
}

/// Use to generate ServerHello with the HandshakeBuilder.
/// Provide the optional / required data to construct it.
pub trait UntypedServerHelloBuilder {
    /// This should return [3, 3] for TLS 1.3
    fn legacy_version(&self) -> &[u8; 2];
    /// Generate 32 bytes server random for the Hello
    fn server_random(&self) -> &[u8; 32];
    /// In TLS 1.3 provide the ClientHello session id (if any) back
    fn legacy_session_id(&self) -> &[u8];
    /// Server selected the cipher suite from client's list.
    fn selected_cipher_suite(&self) -> &[u8; 2];
    /// Server selected compression list. This must be None for TLS 1.3.
    fn selected_legacy_insecure_compression_method(&self) -> Option<u8>;
    /// Extensions used list
    fn extensions_list(&self) -> &[u16];
    /// Given extension relevant encoded data. See [`ytls_extensions`] to encode.
    fn extension_data(&self, ext: u16) -> &[u8];
}
