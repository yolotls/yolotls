//! ytls Parser traits

//----------------------------------------------------------
// Record Parsing
//----------------------------------------------------------

pub trait ClientHelloProcessor {
    fn handle_extension(&mut self, _ext_id: u16, _ext_data: &[u8]) -> ();
    fn handle_cipher_suite(&mut self, _cs: &[u8; 2]) -> ();
    fn handle_client_random(&mut self, _cr: &[u8; 32]) -> ();
    fn handle_session_id(&mut self, _ses_id: &[u8]) -> ();
}
