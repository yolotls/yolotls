//! Record buffer

use crate::builder::b_dhs_encrypted_extensions;
use crate::builder::b_dhs_server_certificate;
use crate::builder::b_dhs_server_certificate_verify;
use crate::builder::b_dhs_server_handshake_finished;
use crate::builder::b_server_hello;

/// Const generic buffer holder for records
#[derive(Debug, PartialEq)]
pub(crate) enum RecordBuffer<const N: usize> {
    /// Handshake, ServerHello [ClearText]
    ServerHello(b_server_hello::BufStaticServerHello<N>),
}

/// Const generic buffer holder for Wrapped records
#[derive(Debug, PartialEq)]
pub(crate) enum WrappedRecordBuffer<const N: usize> {
    /// AppData/Handshake, Server Handshake Finished [CipherText]
    ServerHandshakeFinished(b_dhs_server_handshake_finished::BufStaticServerHandshakeFinished<N>),
    /// AppData/Handshake, Server Certificate/s [CipherText]
    ServerCertificates(b_dhs_server_certificate::BufStaticServerCertificates<N>),
    /// AppData/Handshake, Server Certificate Verify [CipherText]
    ServerCertificateVerify(b_dhs_server_certificate_verify::BufStaticServerCertificateVerify<N>),
    /// Appdata/Handshake, Enrypted Extensions  [CipherText]
    EncryptedExtensions(b_dhs_encrypted_extensions::BufStaticEncryptedExtensions<N>),
}
