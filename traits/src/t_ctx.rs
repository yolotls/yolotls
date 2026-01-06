//! Common Context Impls

use crate::{TlsLeftIn, TlsLeftOut, TlsRight};

/// Marker for Handshake being complete
#[derive(Debug, PartialEq)]
pub struct HandshakeComplete;

/// Implement to process handshaking part
pub trait CtxHandshakeProcessor {
    type Error;
    /// Spin Handshake state forward
    /// # Left
    /// The Left is typically the I/O side allowing the state machine
    /// to complete the handshake required
    /// # Evolution
    /// Once handshake is finished, Some(..) is given for the application
    /// state machinery allowing de/encryption.
    #[must_use]
    fn spin_handshake<Li: TlsLeftIn, Lo: TlsLeftOut>(
        &mut self,
        _left_in: &mut Li,
        _left_out: &mut Lo,
    ) -> Result<Option<HandshakeComplete>, Self::Error>;
    /// Switch to Application context if and when handshake is complete consuming the current context.
    #[must_use]
    fn switch_to_application(self) -> Option<impl CtxApplicationProcessor>;
}

/// Marker for Shutdown being complete
#[derive(Debug, PartialEq)]
pub struct ShutdownComplete;

/// Implement to process application data part
pub trait CtxApplicationProcessor {
    type Error;
    /// Spin Application state forward with the given Left and Right sides.
    /// # Left
    /// Same as in handshake the left is typically the I/O allowing the
    /// state machine to uphold the context alive and encrypt & decrypt
    /// the application traffic.
    /// # Right
    /// Right side allows the application to both provide cleartext to the
    /// state machinery to encrypt egress traffic as well as state machine
    /// to provide the cleartext decrypted traffic to application.
    /// # Evolution
    /// Shutdown is provided when the state machinery can be shut down.
    #[must_use]
    fn spin_application<Li: TlsLeftIn, Lo: TlsLeftOut, R: TlsRight>(
        &mut self,
        _left_in: &mut Li,
        _left_out: &mut Lo,
        _right: &mut R,
    ) -> Result<Option<ShutdownComplete>, Self::Error>;
}
