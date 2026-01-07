//! ytls I/O traits

/// TLS State Machine Left (Ciphertext) or "Network" I/O egress side
pub trait TlsLeftOut {
    /// Send encoded record data out.
    fn send_record_out(&mut self, data: &[u8]) -> ();
}

/// TLS State Machine Left (Ciphertext) or "Network" I/O ingress side
pub trait TlsLeftIn {
    /// Provide the Ingress buffer in
    fn left_buf_in(&self) -> &[u8];
    // State machine requires Left I/O to send out len egress bytes
    //fn left_buf_mark_send_out(&mut self, _len: usize) -> ()
    /// State machine requires Left I/O to discard processed ingress bytes
    fn left_buf_mark_discard_in(&mut self, _len: usize) -> ();
}

/// TLS State Machine Right (Cleartext) or "Application" I/O side
pub trait TlsRight {
    /// State machine provides decrypted traffic
    fn on_decrypted(&mut self, _data: &[u8]) -> ();
    /// State machine asks traffic to be encrypted
    fn on_encrypt(&self) -> &[u8];
    /// State machine requires Right I/O to discard encrypted ingress bytes.
    fn right_buf_mark_discard_out(&mut self, _len: usize) -> ();
}
