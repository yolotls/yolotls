//! Encoder-Formatter-Cursor Utility knife

use crate::error::BuilderError;

// Encoder that safeguards against Max length
// and total length being over u16::MAX
pub(crate) struct EncoderU16<const MAX: usize> {
    encoded: usize,
}

impl<const MAX: usize> EncoderU16<MAX> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self { encoded: 0 }
    }
    #[inline]
    pub(crate) fn cur_as_usize(&self) -> usize {
        self.encoded
    }
    #[inline]
    pub(crate) fn cur_as_u16(&self) -> u16 {
        self.encoded as u16
    }
    // Check increment effect if it overflows
    #[inline]
    fn _check_incr_len(&self, i: usize) -> bool {
        if self.encoded + i > MAX {
            return false;
        }
        if self.encoded + i > u16::MAX as usize {
            return false;
        }
        true
    }
    // Try to skip & increment encoded only e.g. skip bytes
    #[inline]
    pub(crate) fn try_skip_only(&mut self, i: usize) -> Result<usize, BuilderError> {
        if !self._check_incr_len(i) {
            return Err(BuilderError::Overflow);
        }

        self.encoded += i;
        Ok(self.encoded)
    }
    // Try to fill with bytes from the current pos
    #[inline]
    pub(crate) fn try_fill_with(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
    ) -> Result<usize, BuilderError> {
        let i = src.len();
        let dst_len = dst.len();

        if dst_len < i + self.encoded {
            return Err(BuilderError::Overflow);
        }

        if !self._check_incr_len(i) {
            return Err(BuilderError::Overflow);
        }

        let start = self.encoded;
        let end = self.encoded + i;

        dst[start..end].copy_from_slice(src);

        self.encoded += i;
        Ok(self.encoded)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_fill_2_with_ok() {
        let mut b: [u8; 10] = [0; 10];
        let mut e = EncoderU16::<10>::new();

        let r = e.try_fill_with(&mut b, &[1, 2]);
        assert_eq!(r, Ok(2));
        assert_eq!(hex::encode(b), "01020000000000000000");
    }

    #[test]
    fn test_fill_2_skip_3_with_ok() {
        let mut b: [u8; 10] = [0; 10];
        let mut e = EncoderU16::<10>::new();

        let r = e.try_fill_with(&mut b, &[1, 2]);
        assert_eq!(r, Ok(2));
        let r = e.try_skip_only(3);
        assert_eq!(r, Ok(5));
        let r = e.try_fill_with(&mut b, &[9, 8]);
        assert_eq!(r, Ok(7));
        assert_eq!(hex::encode(b), "01020000000908000000");
    }

    #[test]
    fn test_fill_overflow() {
        let mut b: [u8; 1] = [0; 1];
        let mut e = EncoderU16::<1>::new();

        let r = e.try_fill_with(&mut b, &[1, 2]);
        assert_eq!(r, Err(BuilderError::Overflow));
        assert_eq!(hex::encode(b), "00");
    }

    #[test]
    fn test_skip_overflow() {
        let b: [u8; 1] = [0; 1];
        let mut e = EncoderU16::<1>::new();

        let r = e.try_skip_only(2);
        assert_eq!(r, Err(BuilderError::Overflow));
        assert_eq!(hex::encode(b), "00");
    }
}
