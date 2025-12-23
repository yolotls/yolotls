//! ClientHello

use ytls_traits::HelloProcessor;

use crate::error::{RecordError, ClientHelloError};
use super::Extensions;
use super::CipherSuites;

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned};

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
#[derive(Debug)]
pub struct ClientHelloHdr {
    pub(crate) legacy_version: [u8; 2],
    pub(crate) client_random: [u8; 32],
    pub(crate) ses_id_len: u8,
}

#[derive(Debug)]
pub struct ClientHello<'r> {
    pub(crate) hdr: &'r ClientHelloHdr,
}

impl<'r> ClientHello<'r> {
    pub fn parse<P: HelloProcessor>(prc: &mut P, bytes: &'r [u8]) -> Result<(Self, &'r [u8]), RecordError> {
        let (hello_hdr, mut rest) = ClientHelloHdr::try_ref_from_prefix(bytes)
            .map_err(|e| RecordError::from_zero_copy(e))?;
        
        let ses_id_len: usize = hello_hdr.ses_id_len.into();
        
        if ses_id_len > 32 {
            return Err(RecordError::ClientHello(ClientHelloError::OverflowSesId));
        }
        
        rest = &rest[ses_id_len..];
        let lenb: [u8; 2] = [rest[0], rest[1]];
        let cipher_suite_len = N16::from_bytes(lenb);
        
        if cipher_suite_len > 65534 {
            return Err(RecordError::ClientHello(ClientHelloError::OverflowCipherSuites));
        }
        
        rest = &rest[2..];
        let (cipher_suites, rest_next) = rest.split_at(cipher_suite_len.into());
        rest = rest_next;
        
        CipherSuites::parse_cipher_suites(prc, cipher_suites)
            .map_err(|e| RecordError::ClientHello(ClientHelloError::CipherSuites(e)))?;

        // skip compressors parsing - add them in if someone needs them
        // Note: Compressors have security related issues and was removed in TLS 1.3
        let compressors_len = rest[0];
        rest = &rest[1..];
        let (_compressors, rest_next) = rest.split_at(compressors_len.into());
		rest = rest_next;

        let extensions_len = N16::from_bytes([rest[0], rest[1]]);
        rest = &rest[2..];
        let (extensions, rest_next) = rest.split_at(extensions_len.into());
        rest = rest_next;
        
        Extensions::parse_extensions(prc, extensions)
            .map_err(|e| RecordError::ClientHello(ClientHelloError::Extensions(e)))?;
        
        Ok((ClientHello { hdr: hello_hdr }, rest))
    }
}
