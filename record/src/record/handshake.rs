//! Handhsake Record

use ytls_traits::ClientHelloProcessor;
use ytls_traits::ServerApRecordProcessor;
use ytls_traits::ServerRecordProcessor;
use ytls_traits::ServerWrappedRecordProcessor;

mod extensions;
pub use extensions::Extensions;
mod cipher_suites;
pub use cipher_suites::CipherSuites;

mod client_hello;
pub use client_hello::ClientHello;

mod server_hello;
pub use server_hello::ServerHello;

mod server_certificate;
pub use server_certificate::ServerCertificate;

mod server_certificate_verify;
pub use server_certificate_verify::ServerCertificateVerify;

mod client_finished;
pub use client_finished::ClientFinished;

mod server_finished;
pub use server_finished::ServerFinished;

use crate::error::RecordError;

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[derive(Debug, PartialEq)]
pub enum HandshakeType {
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    MessageHash,
    Unknown(u8),
}

impl From<HandshakeType> for &'static str {
    fn from(t: HandshakeType) -> &'static str {
        match t {
            HandshakeType::ClientHello => "ClientHello",
            HandshakeType::ServerHello => "ServerHello",
            HandshakeType::NewSessionTicket => "NewSessionTicket",
            HandshakeType::EndOfEarlyData => "EndOfEarlyData",
            HandshakeType::EncryptedExtensions => "EncryptedExtensins",
            HandshakeType::Certificate => "Certificate",
            HandshakeType::CertificateRequest => "CertificateRequest",
            HandshakeType::CertificateVerify => "CertificateVerify",
            HandshakeType::Finished => "Finished",
            HandshakeType::KeyUpdate => "KeyUpdate",
            HandshakeType::MessageHash => "MessageHash",
            HandshakeType::Unknown(_) => "Unknown",
        }
    }
}

impl From<u8> for HandshakeType {
    fn from(s: u8) -> HandshakeType {
        match s {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            13 => Self::CertificateRequest,
            15 => Self::CertificateVerify,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            254 => Self::MessageHash,
            _ => Self::Unknown(s),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MsgType<'r> {
    ClientHello(ClientHello<'r>),
    ServerHello(ServerHello<'r>),
    ClientFinished(ClientFinished<'r>),
    EncryptedExtensions,
    ServerCertificate,
    ServerCertificateVerify,
    ServerFinished,
    NewSessionTicket,
}

#[derive(Debug, PartialEq)]
pub struct HandshakeMsg<'r> {
    pub req_ctx: Option<u8>,
    pub msg: MsgType<'r>,
}

#[inline]
fn parse_header(mut rest: &[u8]) -> Result<(HandshakeType, Option<u8>, usize, &[u8]), RecordError> {
    let msg_type_raw = rest.split_off(..1).ok_or(RecordError::Size)?;

    let msg_type: HandshakeType = msg_type_raw[0].into();

    if let HandshakeType::Unknown(_) = msg_type {
        return Err(RecordError::Validity);
    }

    let mut req_ctx: Option<u8> = None;

    if let HandshakeType::Certificate = msg_type {
        let req_ctx_t = rest.split_off(..1).ok_or(RecordError::Size)?;
        req_ctx = Some(req_ctx_t[0]);
    }

    let msg_len_b = rest.split_off(..3).ok_or(RecordError::Size)?;

    let msg_len = u32::from_be_bytes([0, msg_len_b[0], msg_len_b[1], msg_len_b[2]]);

    Ok((msg_type, req_ctx, msg_len as usize, rest))
}

impl<'r> HandshakeMsg<'r> {
    /// The inner Message
    pub fn msg(&'r self) -> &'r MsgType<'r> {
        &self.msg
    }
    /// Parse Server Wrapped Record (Application phase)
    #[inline]
    pub fn server_wrapped_ap_parse<P: ServerApRecordProcessor>(
        _prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<Self, RecordError> {
        let (msg_type, req_ctx, _msg_len, _rest) = parse_header(bytes)?;

        let msg: MsgType<'_> = match msg_type {
            HandshakeType::NewSessionTicket => MsgType::NewSessionTicket,
            _ => {
                return Err(RecordError::NotImplemented(
                    msg_type.into(),
                    "HandshakeMsg::client_wrapped_ap_parse",
                ))
            }
        };
        Ok(Self { req_ctx, msg })
    }
    /// Parse Server Wrapped Record (Handshake phase)
    #[inline]
    pub fn server_wrapped_hs_parse<P: ServerWrappedRecordProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<Self, RecordError> {
        let (msg_type, req_ctx, _msg_len, rest) = parse_header(bytes)?;

        let msg = match msg_type {
            HandshakeType::EncryptedExtensions => {
                // TODO: support these
                match rest {
                    &[0, 0] => {}
                    _ => return Err(RecordError::Validity),
                }
                MsgType::EncryptedExtensions
            }
            HandshakeType::Certificate => {
                ServerCertificate::parse_wrapped(prc, rest)?;
                MsgType::ServerCertificate
            }
            HandshakeType::CertificateVerify => {
                ServerCertificateVerify::parse_wrapped(prc, rest)?;
                MsgType::ServerCertificateVerify
            }
            HandshakeType::Finished => {
                ServerFinished::parse_wrapped(prc, rest)?;
                MsgType::ServerFinished
            }
            _ => {
                return Err(RecordError::NotImplemented(
                    msg_type.into(),
                    "HandshakeMsg::server_wrapped_parse",
                ))
            }
        };

        Ok(Self { req_ctx, msg })
    }
    /// Parse Client Wrapped Record
    pub fn client_wrapped_parse(bytes: &'r [u8]) -> Result<Self, RecordError> {
        let (msg_type, req_ctx, _msg_len, rest) = parse_header(bytes)?;

        let msg = match msg_type {
            HandshakeType::ClientHello => return Err(RecordError::NotAllowed),
            HandshakeType::Finished => {
                let c_finished = ClientFinished::parse_wrapped(rest)?;
                MsgType::ClientFinished(c_finished)
            }
            _ => {
                return Err(RecordError::NotImplemented(
                    msg_type.into(),
                    "HandshakeMsg::client_wrapped_parse",
                ))
            }
        };

        Ok(Self { req_ctx, msg })
    }
    /// Parse Server Record
    pub fn server_parse<P: ServerRecordProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<(Self, &'r [u8]), RecordError> {
        let (msg_type, req_ctx, _msg_len, rest) = parse_header(bytes)?;

        let (msg, rest_next) = match msg_type {
            HandshakeType::ServerHello => {
                let (s_hello, r_next) = ServerHello::parse(prc, rest)?;
                (MsgType::ServerHello(s_hello), r_next)
            }
            _ => {
                return Err(RecordError::NotImplemented(
                    msg_type.into(),
                    "HandshakeMsg::server_parse",
                ))
            }
        };

        Ok((Self { req_ctx, msg }, rest_next))
    }
    /// Parse Client Record
    pub fn client_parse<P: ClientHelloProcessor>(
        prc: &mut P,
        bytes: &'r [u8],
    ) -> Result<(Self, &'r [u8]), RecordError> {
        let (msg_type, req_ctx, _msg_len, rest) = parse_header(bytes)?;

        let (msg, rest_next) = match msg_type {
            HandshakeType::ClientHello => {
                let (c_hello, r_next) = ClientHello::parse(prc, rest)?;
                (MsgType::ClientHello(c_hello), r_next)
            }
            _ => {
                return Err(RecordError::NotImplemented(
                    msg_type.into(),
                    "HandshakeMsg::client_parse",
                ))
            }
        };

        Ok((Self { req_ctx, msg }, rest_next))
    }
}
