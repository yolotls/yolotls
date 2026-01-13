//! Server Finished Handshake record

use crate::RecordError;
use ytls_traits::ServerFinishedProcessor;
use ytls_traits::ServerWrappedRecordProcessor;

#[derive(Debug, PartialEq)]
pub struct ServerFinished;

impl ServerFinished {
    /// Parse wrapped Server Certificate
    #[inline]
    pub fn parse_wrapped<P: ServerWrappedRecordProcessor>(
        prc: &mut P,
        raw: &[u8],
    ) -> Result<(), RecordError> {
        let sh = prc.server_finished();

        sh.handle_server_finished(raw);

        Ok(())
    }
}
