//! errors

#[derive(Debug, PartialEq)]
pub enum TlsExtError {
    /// Invalid Extension data length
    InvalidLength,
    /// No available data (e.g. empty)
    NoData,
    /// One of the entries overflows
    EntryOverflow,
}
