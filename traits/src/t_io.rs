//! ytls Main traits

//----------------------------------------------------------
// SendOut is required for I/O layer linkage
//----------------------------------------------------------

/// TLS State Machine Left (Ciphertext) or "Network" I/O side
pub trait TlsLeft {
    /// Send encoded record data out.
    fn send_record_out(&mut self, data: &[u8]) -> ();
}
