//! Wrapped Record

use crate::error::RecordError;

#[derive(Debug, PartialEq)]
pub enum WrappedContentType {
    /// Change Cipher Spec
    ChangeCipherSpec,
    /// Alert
    Alert,
    /// Handshake
    Handshake,
    /// Application Data
    ApplicationData,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for WrappedContentType {
    fn from(i: u8) -> Self {
        match i {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => Self::Unknown(i),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct WrappedRecord<'r> {
    raw_bytes: &'r [u8],
    msg: WrappedMsgType<'r>,
}

#[derive(Debug, PartialEq)]
pub enum WrappedMsgType<'r> {
    Handshake(HandshakeMsg<'r>),
}

use crate::HandshakeMsg;

impl<'r> WrappedRecord<'r> {
    #[inline]
    pub fn msg(&self) -> &WrappedMsgType<'r> {
        &self.msg
    }
    #[inline]
    pub fn parse_client(wrapped_data: &'r [u8]) -> Result<WrappedRecord<'r>, RecordError> {
        let w_len = wrapped_data.len();

        let rec_type: WrappedContentType = wrapped_data[w_len - 1].into();
        let raw_bytes = &wrapped_data[0..w_len - 1];

        let msg = match rec_type {
            WrappedContentType::Handshake => {
                let msg = HandshakeMsg::client_wrapped_parse(raw_bytes)?;
                WrappedMsgType::Handshake(msg)
            }
            WrappedContentType::Unknown(_) => return Err(RecordError::Validity),
            _ => todo!(),
        };
        Ok(WrappedRecord { raw_bytes, msg })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;

    use crate::ClientFinished;

    #[rstest]
    #[case(
        &hex!("14000020a0210258e7c4402ab07807a1e61df4cf0ab58f828b26c6adf29654228ac0b66f16"),
    )]
    fn wrapped_ok(#[case] in_data: &[u8]) {
        let r = WrappedRecord::parse_client(in_data);
        insta::assert_debug_snapshot!(r);
    }

    #[rstest]
    #[case(&hex!("7710"))]
    #[case(&hex!("1410"))]
    #[case(&hex!("140010"))]
    #[case(&hex!("14000010"))]
    fn wrapped_err(#[case] in_data: &[u8]) {
        assert_eq!(
            WrappedRecord::parse_client(in_data),
            Err(RecordError::Validity)
        );
    }
}
