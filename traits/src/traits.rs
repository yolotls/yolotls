//! ytls traits

//----------------------------------------------------------
// Record Parsing
//----------------------------------------------------------

pub trait ClientHelloProcessor {
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> ();
    fn handle_cipher_suite(&mut self, cs: &[u8; 2]) -> ();
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
