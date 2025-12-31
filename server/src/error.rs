//! errors

use ytls_record::BuilderError;
use ytls_record::RecordError;

/// yTLS Server Context Errors
#[derive(Debug, PartialEq)]
pub enum TlsServerCtxError {
    Record(RecordError),
    Builder(BuilderError),
    Bug(&'static str),
    UnexpectedAppData,
}
