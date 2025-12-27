//! Record Builders

mod b_server_hello;
mod formatter;

use crate::error::BuilderError;

use ytls_traits::UntypedHandshakeBuilder;
use ytls_traits::UntypedServerHelloBuilder;

#[derive(Debug, PartialEq)]
pub enum RecordBuffer<const N: usize> {
    ServerHello(b_server_hello::BufStaticServerHello<N>),
}

/// Provides statically allocated Record Builder based on worst case
/// estimation of the maximum size of record.
/// Typically record sizes need to be also limited based on the record
/// limit extension but this has to be done in runtime.
#[derive(Debug, PartialEq)]
pub struct StaticRecordBuilder<const N: usize> {
    rec_buf: RecordBuffer<N>,
}

impl<const N: usize> UntypedHandshakeBuilder for StaticRecordBuilder<N> {
    type Error = BuilderError;
    /// Construct a Handshake record featuring a Server Hello from untyped raw data.
    #[inline]
    fn server_hello_untyped<S: UntypedServerHelloBuilder>(s: &S) -> Result<Self, Self::Error> {
        Ok(Self {
            rec_buf: RecordBuffer::<N>::ServerHello(
                b_server_hello::BufStaticServerHello::<N>::static_from_untyped(s)?,
            ),
        })
    }
    fn without_header_as_bytes(&self) -> &[u8] {
        match self.rec_buf {
            RecordBuffer::ServerHello(ref h) => &h.as_without_header_ref(),
        }
    }
    fn as_encoded_bytes(&self) -> &[u8] {
        match self.rec_buf {
            RecordBuffer::ServerHello(ref h) => &h.as_ref(),
        }
    }
}
