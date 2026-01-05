//! ytls Main traits

//----------------------------------------------------------
// SendOut is required for I/O layer linkage
//----------------------------------------------------------

/// TLS State Machine Left (Ciphertext) or "Network" I/O side
pub trait TlsLeftOut {
    /// Send encoded record data out.
    fn send_record_out(&mut self, data: &[u8]) -> ();
}

pub trait TlsLeftIn {
    /// Provide the Ingress buffer in
    fn left_buf_in(&self) -> &[u8];
    // State machine requires Left I/O to send out len egress bytes
    //fn left_buf_mark_send_out(&mut self, _len: usize) -> ()
    /// State machine requires Left I/O to discard processed ingress bytes
    fn left_buf_mark_discard_in(&mut self, _len: usize) -> ();
}

/// TLS State Machine Left (Cleartext) or "Application" I/O side
pub trait TlsRight {}
