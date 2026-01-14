//! Record buffer

use crate::builder::b_client_hello::BufStaticClientHello;
use crate::builder::b_dhs_client_handshake_finished::BufStaticClientHandshakeFinished;
use crate::builder::b_dhs_encrypted_extensions::BufStaticEncryptedExtensions;
use crate::builder::b_dhs_server_certificate::BufStaticServerCertificates;
use crate::builder::b_dhs_server_certificate_verify::BufStaticServerCertificateVerify;
use crate::builder::b_dhs_server_handshake_finished::BufStaticServerHandshakeFinished;
use crate::builder::b_server_hello::BufStaticServerHello;
use crate::builder::b_wrap_application_data::BufStaticAppData;

/// Const generic buffer holder for records
#[derive(Debug, PartialEq)]
pub(crate) enum RecordBuffer<const N: usize> {
    /// Handshake, ClientHello [ClearText]
    ClientHello(BufStaticClientHello<N>),
    /// Handshake, ServerHello [ClearText]
    ServerHello(BufStaticServerHello<N>),
}

/// Const generic buffer holder for Wrapped records
#[derive(Debug, PartialEq)]
pub(crate) enum WrappedAppRecordBuffer<const N: usize> {
    /// AppData/Appdata
    AppData(BufStaticAppData<N>),
}

/// Const generic buffer holder for Wrapped records
#[derive(Debug, PartialEq)]
pub(crate) enum WrappedRecordBuffer<const N: usize> {
    /// AppData/Handshake, Client Handshake Finished [CipherText]
    ClientHandshakeFinished(BufStaticClientHandshakeFinished<N>),
    /// AppData/Handshake, Server Handshake Finished [CipherText]
    ServerHandshakeFinished(BufStaticServerHandshakeFinished<N>),
    /// AppData/Handshake, Server Certificate/s [CipherText]
    ServerCertificates(BufStaticServerCertificates<N>),
    /// AppData/Handshake, Server Certificate Verify [CipherText]
    ServerCertificateVerify(BufStaticServerCertificateVerify<N>),
    /// Appdata/Handshake, Enrypted Extensions  [CipherText]
    EncryptedExtensions(BufStaticEncryptedExtensions<N>),
}
