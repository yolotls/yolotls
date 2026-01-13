//! ServerHello

use ytls_traits::ServerHelloProcessor;
use ytls_traits::ServerRecordProcessor;

use super::CipherSuites;
use super::Extensions;
use crate::error::{RecordError, ServerHelloError};

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct ServerHelloHdr {
    pub(crate) legacy_version: [u8; 2],
    pub(crate) server_random: [u8; 32],
    pub(crate) ses_id_len: u8,
}

#[derive(Debug, PartialEq)]
pub struct ServerHello<'r> {
    pub(crate) hdr: &'r ServerHelloHdr,
}

impl<'r> ServerHello<'r> {
    pub fn parse<P: ServerRecordProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<(Self, &'r [u8]), RecordError> {
        let (hello_hdr, mut rest) = ServerHelloHdr::try_ref_from_prefix(bytes)
            .map_err(|e| RecordError::from_zero_copy(e))?;

        let sh = prc.server_hello();

        sh.handle_server_random(&hello_hdr.server_random);

        let ses_id_len: usize = hello_hdr.ses_id_len.into();

        if ses_id_len > 32 {
            return Err(RecordError::OverflowLength);
        }

        let ses_id = rest.split_off(..ses_id_len).ok_or(RecordError::Size)?;
        sh.handle_session_id(&ses_id);

        let cipher_suite = rest.split_off(..2).ok_or(RecordError::Size)?;
        sh.handle_selected_cipher_suite([cipher_suite[0], cipher_suite[1]]);

        let _compress_method = rest.split_off(..1).ok_or(RecordError::Size)?;

        let ext_len_s = rest.split_off(..2).ok_or(RecordError::Size)?;
        let extensions_length = u16::from_be_bytes([ext_len_s[0], ext_len_s[1]]);

        let extensions = rest
            .split_off(..extensions_length as usize)
            .ok_or(RecordError::Size)?;

        Extensions::parse_server_extensions(prc, extensions)
            .map_err(|e| RecordError::ServerHello(ServerHelloError::Extensions(e)))?;

        Ok((ServerHello { hdr: hello_hdr }, rest))
    }
}
