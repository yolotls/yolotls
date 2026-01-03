//! ytls Builder traits

//----------------------------------------------------------
// Record Building
//----------------------------------------------------------

/// Non-typed Handshake Builder with raw data inputs.
/// This is implemented by the [`ytls_record::Record`] where as
/// the required inputs are through the client/server contextes.
pub trait HandshakeBuilder {
    type Error;
    /// Build Server Hello
    fn server_hello_untyped<S: ServerHelloBuilder>(_: &S) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Provide the raw encoded bytes but without header
    fn as_hashing_context(&self) -> &[u8];
    /// Provide the raw encoded bytes
    fn as_encoded_bytes(&self) -> &[u8];
}

/// Same except non-wrapped but where we wrap the record into
/// TLS 1.2 Application Data layer, typically encrypted when
/// written to wire.
pub trait WrappedHandshakeBuilder {
    type Error;
    /// Build Server Handshake Finished
    fn server_handshake_finished<S: ServerHandshakeFinishedBuilder>(
        _: &S,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Build Server Certificates
    fn server_certificates<S: ServerCertificatesBuilder>(_: &S) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Build Server Certificate Verify of which we have the private key of
    fn server_certificate_verify<S: ServerCertificateVerifyBuilder>(
        _: &S,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Build Encrypted Extensions
    fn encrypted_extensions<S: EncryptedExtensionsBuilder>(s: &S) -> Result<Self, Self::Error>
    where
        Self: Sized;
    /// Get disjoint mut for AEAD use of 1) additional data 2) cleartext data to encrypt
    fn as_disjoint_mut_for_aead(&mut self) -> Result<[&mut [u8]; 2], Self::Error>;
    /// Set the AEAD authenticated tag of this wrapped record after encryption
    fn set_auth_tag(&mut self, new_tag: &[u8; 16]) -> ();
    /// Provide the cleartext as mutable in order for it to be encrypted into ciphertext.
    fn as_ciphertext_mut(&mut self) -> &mut [u8];
    /// Provides the missing handshake header for hashing purposes
    /// which must be included in the transcript hash.
    fn wrapped_hash_header_ref(&self) -> [u8; 5];
    /// Provide the raw encoded bytes for hashing purposes which
    /// includes the cleartext portition that will be encrypted
    /// except the wrapped handshake header which must be hashed
    /// separately through wrapped_hash_header_ref due to
    /// to-be-encrypted records being "wrapped" over TLS 1.2 appdata.
    fn as_hashing_context_ref(&self) -> &[u8];
    /// Provide the full raw encoded bytes including placeholder
    /// tag and record headers
    fn as_encoded_bytes(&self) -> &[u8];
}

/// Server handshake finished is provided through trait implementation
pub trait ServerHandshakeFinishedBuilder {
    /// Provide the hash
    fn hash_finished(&self) -> &[u8];
}

/// Server certificate verification is provided through trait implementation
pub trait ServerCertificateVerifyBuilder {
    /// Provide the signature algorithm used
    fn signature_algorithm(&self) -> [u8; 2];
    /// Sign the current handshake hash with the used signature
    /// algorithm and the server private key used to generate the public key
    /// within the server certificate.
    fn sign_cert_verify(&self) -> &[u8];
}

/// Server certificates are provided through trait implementation
pub trait ServerCertificatesBuilder {
    /// Provide ordered list of certificates and their internal id
    fn server_certs_list(&self) -> &[u8];
    /// Provide the ASN.1 DER encoded certificate by the given cert id
    fn server_cert_data(&self, _id: u8) -> &[u8];
    /// Provide any certificate extensions if any by the given cert id.
    fn server_cert_extensions(&self, _id: u8) -> &[u8];
}

/// Encrypted Extensions are provided through trait implementation if any
pub trait EncryptedExtensionsBuilder {
    // TODO
    // Provide the encrypted extensions list if any
    //fn encrypted_extension_list(&self) -> &[u16];
}

/// Use to generate ServerHello with the HandshakeBuilder.
/// Provide the optional / required data to construct it.
pub trait ServerHelloBuilder {
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
