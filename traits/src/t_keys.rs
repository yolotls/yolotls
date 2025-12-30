//! yTLS Key related traits
//! Implement to provide TLS1.3 Key Schedule per RFC 8446 s. 7.1
//! The trait is split in order to provide typed triggers to clean
/// up old secrets when not needed anymore beyond their purpose.

//use crate::CryptoConfig;

/// Initialize TLS1.3 Key Schedule
pub trait Tls13KeyScheduleInit {
    /// Init TLS1.3 Key Schedule with the given cryptography that includes Hkdf<Sha256> processor.
    /// Select this if your AEAD cipher has _SHA256 suffix and no PSK
    fn no_psk_with_crypto_and_sha256() -> impl Tls13KeyScheduleDerivedSha256;
}

/// TLS1.3 "derived" Key Schedule
pub trait Tls13KeyScheduleDerivedSha256 {
    /// Proceed to handshake secret with the given Input (1) x25519 shared secret
    ///
    /// ## Hash Input (2)
    ///
    /// The result hash of the combined ClientHello and ServerHello.
    ///
    /// ## Returns None upon incorrect input
    ///
    /// If the Input hash is incompatible with the initially provided hash
    /// this will return None.
    fn dh_x25519(self, _shared_secret: &[u8; 32], _input_hash: &[u8; 32]) -> impl Tls13KeyScheduleHandshakeSha256;
}

/// TLS1.3 "handshake" Key Schedule
/// # Note
/// Input mutable key or iv input must be the same length as the used
/// cipher suite relevant input secret key or iv.
pub trait Tls13KeyScheduleHandshakeSha256 {
    /// Expands Key for the Server AEAD sender.
    fn handshake_server_key(&self, _key: &mut [u8]) -> ();
    /// Expands Key for the Client AEAD sender.
    fn handshake_client_key(&self, _key: &mut [u8]) -> ();
    /// Expands Nonce / IV for the Server AEAD sender.
    fn handshake_server_iv(&self, _iv: &mut [u8]) -> ();
    /// Expands Nonce IV for the Client AEAD sender.
    fn handshake_client_iv(&self, _iv: &mut [u8]) -> ();
    /// Upon finishing handshake, proceed to Master Key schedule with the final hash of the hanshakes.
    ///
    /// ## Hash Input
    ///
    /// The complete hash result of all handshake messages from ClientHello to finished.
    fn finished_handshake(self, _handshake_hash: &[u8; 32]) -> impl Tls13KeyScheduleApSha256;
}

/// TLS1.3 "Main" Key Schedule for Application Traffic post-handshake.
/// # Note
/// Input mutable key or iv input must be the same length as the used
/// cipher suite relevant input secret key or iv.
pub trait Tls13KeyScheduleApSha256 {
    /// Expands Key for the Server AEAD sender.
    fn application_server_key(&self, _key: &mut [u8]) -> ();
    /// Expands Key for the Client AEAD sender.
    fn application_client_key(&self, _key: &mut [u8]) -> ();
    /// Expands IV for the Server AEAD sender.
    fn application_server_iv(&self, _iv: &mut [u8]) -> ();
    /// Expands IV for the Client AEAD sender.
    fn application_client_iv(&self, _iv: &mut [u8]) -> ();
}

// TODO: Updated traffic keys
