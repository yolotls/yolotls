//! Handhsake Record

use ytls_traits::ClientHelloProcessor;

mod extensions;
pub use extensions::Extensions;
mod cipher_suites;
pub use cipher_suites::CipherSuites;

mod client_hello;
pub use client_hello::ClientHello;

use crate::error::RecordError;

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
#[derive(Debug)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
#[derive(Debug)]
pub struct HandshakeHdr {
    msg_type: HandshakeType,
    msg_length: [u8; 3],
}

#[derive(Debug)]
pub enum MsgType<'r> {
    ClientHello(ClientHello<'r>),
}

#[derive(Debug)]
pub struct HandshakeMsg<'r> {
    hdr: &'r HandshakeHdr,
    msg: MsgType<'r>,
}

impl<'r> HandshakeMsg<'r> {
    /// The inner Message
    pub fn msg(&'r self) -> &'r MsgType<'r> {
        &self.msg
    }
    /// Parse Client Record
    pub fn client_parse<P: ClientHelloProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<(Self, &'r [u8]), RecordError> {
        let (hdr, rest) =
            HandshakeHdr::try_ref_from_prefix(bytes).map_err(|e| RecordError::from_zero_copy(e))?;

        let (msg, rest_next) = match hdr.msg_type {
            HandshakeType::ClientHello => {
                let (c_hello, r_next) = ClientHello::parse(prc, rest)?;
                (MsgType::ClientHello(c_hello), r_next)
            }
            _ => todo!(),
        };

        Ok((Self { hdr, msg }, rest_next))
    }
}
