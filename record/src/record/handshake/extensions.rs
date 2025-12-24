//! Extensions parsing

use ytls_traits::ClientHelloProcessor;

use crate::error::ExtensionsError;

use zerocopy::byteorder::network_endian::U16 as N16;

pub struct Extensions {}

impl Extensions {
    pub fn parse_client_extensions<P: ClientHelloProcessor>(
        prc: &mut P,
        bytes: &[u8],
    ) -> Result<(), ExtensionsError> {
        let mut remaining = bytes;

        let mut parsed_total = 0;
        let to_parse = bytes.len();

        loop {
            if remaining.len() < 4 {
                break;
            }
            let extension_id: usize = N16::from_bytes([remaining[0], remaining[1]]).into();
            let extension_len = N16::from_bytes([remaining[2], remaining[3]]);
            remaining = &remaining[4..];

            parsed_total += 4;

            let extension_len_usize: usize = extension_len.into();

            parsed_total += extension_len_usize;

            if extension_len_usize > remaining.len() {
                return Err(ExtensionsError::OverflowExtensionLen);
            }

            let extension_data = if extension_len_usize == remaining.len() {
                remaining
            } else {
                let (extension_data, remaining_next) = remaining.split_at(extension_len.into());
                remaining = &remaining_next;
                extension_data
            };

            prc.handle_extension(extension_id as u16, extension_data);

            if parsed_total == to_parse {
                break;
            }
        }
        Ok(())
    }
}
