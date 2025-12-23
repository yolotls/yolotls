mod handshake;
#[doc(inline)]
pub use handshake::HandshakeMsg;

use crate::error::RecordError;

use zerocopy::byteorder::network_endian::U16 as N16;
use zerocopy::{TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned};

use ytls_traits::HelloProcessor;

/// TLS Record Conten Type
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(u8)]
#[derive(Debug)]
pub enum ContentType {
    /// Change Cipher Spec
    ChangeCipherSpec = 20,
    /// Alert
    Alert = 21,
    /// Handshake
    Handshake = 22,
    /// Application Data
    ApplicationData = 23,
}

/// TLS Record Layer header
#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
#[derive(Debug)]
pub struct RecordHeader {
    content_type: ContentType,
    legacy_version: [u8; 2],
    record_length: N16,
}

/// TLS Record Layer captured information
#[derive(Debug)]
pub struct Record<'r> {
    header: &'r RecordHeader,
    content: Content<'r>,
}

/// Content of the underlying Record
#[derive(Debug)]
pub enum Content<'r> {
    /// Record is a handshake
    Handshake(HandshakeMsg<'r>),
}

impl<'r> Record<'r> {
    /// Parse incoming byte slices into TLS Record types with the given HelloProcessor.
    pub fn parse<P: HelloProcessor>(prc: &mut P, bytes: &'r [u8]) -> Result<(Record<'r>, &'r [u8]), RecordError> {
        let (hdr, rest) = RecordHeader::try_ref_from_prefix(bytes)            
            .map_err(|e| RecordError::from_zero_copy(e))?;

        if hdr.record_length > 16384 {
            return Err(RecordError::OverflowLength);
        }

        let (content, rest_next) = match hdr.content_type {
            ContentType::Handshake => {
                let (c, r_next) = HandshakeMsg::parse(prc, rest).unwrap();
                (Content::Handshake(c), r_next)
            },
            _ => todo!(),
        };
            
        Ok((Self { header: hdr, content }, rest_next))
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use hex_literal::hex;

    #[derive(Debug, PartialEq)]
    struct Tester {
        suites_encountered: Vec<[u8; 2]>,
        extensions_encountered: Vec<u16>,
    }
    impl HelloProcessor for Tester {
        fn handle_extension(&mut self, ext_id: u16, _ext_data: &[u8]) -> () {
            self.extensions_encountered.push(ext_id);
        }
        fn handle_cipher_suite(&mut self, cipher_suite: &[u8]) -> () {
            self.suites_encountered.push([cipher_suite[0], cipher_suite[1]]);
        }
    }
    
    #[test]
    fn test_firefox_handshake_client_hello() {
        let mut tester = Tester { suites_encountered: vec![], extensions_encountered: vec![] };
        let data = hex!("16030102970100029303030b77e4fa04ceb4dc026c74213fe2a55c14883219b9e6f7b0b503ee2b4a331d842065dcc0babe8c401c1e8afe1f5e40e54155dd0f28e1c7be6e2326143f89bcd95d0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f003501000228000000150013000010746573742e72757374637279702e746f00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a00080403050306030203001200000033006b0069001d0020978142d12fa56febea3f967a43cf5accea191ce4cd5dcfe9d1fd7a5817bbc72700170041043d89d5b8f29cb5c29230bcc6eae0c2890f489724426bd26e2a72581231956ae99117c739f4d24d564143a732a73e92421b49ff51a9c44f729460f6ee251e537b002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001fe0d01190000010003af0020e80e102405db3ad2cfb267f6e11556f1f8b6364f5a02b07897b8eaee4e0d5a1900efe3b3a5d24df62d045ab566ba61536b5443cec82be022b712882204f783afe7c7eb59b93e6b9d30d623fe9a85d0895936be8f85d54818e9a06889e6ed53e3d5aa94e0812c872d5eb40277f6d2b9c1afdbab70bc7da5d6281d2632895855675bc5e7ddadd6aefec02342135082950c430deb6c4ce3d9294929271722aaddb06a7770594ec2bd395378e061b292dfdaa537e2535ca7ee5c698991f8dd8b5c227295e2ceccb7a9b84db5cadcb055f1ef019d6699f76959260a0a49574d18456be3936e74f76d3e5e5b418ddc45b2b219cee91c9ddf0c58dd3c0fb87d954cb59a43d897ed11f7ea0a51fb7b093ad547d2b0");
        let (r, rest) = Record::parse(&mut tester, &data).unwrap();

        insta::assert_debug_snapshot!(r);
        assert_eq!(rest.len(), 0);
    }
}
