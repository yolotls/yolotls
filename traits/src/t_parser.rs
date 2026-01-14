//! ytls Parser traits

//----------------------------------------------------------
// Record Parsing
//----------------------------------------------------------

pub trait ServerApRecordProcessor {}

pub trait ServerWrappedRecordProcessor {
    type ServerCertificateHandler: ServerCertificateProcessor;
    type ServerCertificateVerifyHandler: ServerCertificateVerifyProcessor;
    type ServerFinishedHandler: ServerFinishedProcessor;
    fn server_certificate(&mut self) -> &mut Self::ServerCertificateHandler;
    fn server_certificate_verify(&mut self) -> &mut Self::ServerCertificateVerifyHandler;
    fn server_finished(&mut self) -> &mut Self::ServerFinishedHandler;
}

pub trait ServerFinishedProcessor {
    fn handle_server_finished(&mut self, _hash_finished: &[u8]) -> ();
}

pub trait ServerCertificateProcessor {
    fn handle_server_certificate(&mut self, _cert_data: &[u8], _ext_data: &[u8]) -> ();
}

pub trait ServerCertificateVerifyProcessor {
    fn handle_server_certificate_verify(&mut self, _alg: [u8; 2], _signature: &[u8]) -> ();
}

pub trait ServerRecordProcessor {
    type ServerHelloHandler: ServerHelloProcessor;
    fn server_hello(&mut self) -> &mut Self::ServerHelloHandler;
}

pub trait ServerHelloProcessor {
    fn handle_server_random(&mut self, _sr: &[u8; 32]) -> ();
    fn handle_session_id(&mut self, _ses_id: &[u8]) -> ();
    fn handle_selected_cipher_suite(&mut self, _cipher_suite: [u8; 2]) -> ();
    fn handle_extension(&mut self, _ext_id: u16, _ext_data: &[u8]) -> ();
}

pub trait ClientHelloProcessor {
    fn handle_extension(&mut self, _ext_id: u16, _ext_data: &[u8]) -> ();
    fn handle_cipher_suite(&mut self, _cs: &[u8; 2]) -> ();
    fn handle_client_random(&mut self, _cr: &[u8; 32]) -> ();
    fn handle_session_id(&mut self, _ses_id: &[u8]) -> ();
}
