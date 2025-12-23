//! ytls traits

pub trait HelloProcessor {
    fn handle_extension(&mut self, ext_id: u16, ext_data: &[u8]) -> ();
    fn handle_cipher_suite(&mut self, cs: &[u8]) -> ();
}
