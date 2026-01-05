//! Client finished

use crate::RecordError;

/// Client Finished
#[derive(Debug, PartialEq)]
pub struct ClientFinished<'r> {
    pub hmac: &'r [u8],
}

impl<'r> ClientFinished<'r> {
    pub fn hmac(&self) -> &[u8] {
        self.hmac
    }
    #[inline]
    pub fn parse_wrapped(bytes: &'r [u8]) -> Result<Self, RecordError> {
        // no parsing as it's inside as-is wrapped record always
        let hmac = &bytes;

        Ok(Self { hmac })
    }
}
