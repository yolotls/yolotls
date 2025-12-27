//! Byte Slices handling

/// Non-continuous borrowed byte slices. Final destination
/// will typically copy into continuous "worst case" slice once.
pub enum ByteSlices<'r> {
    /// Single continuous slice
    Single(&'r [u8]),
    /// Non-continuous Double of continuous slices
    Double(&'r [u8], &'r [u8]),
    /// Non-continuos Triple of continuous slices
    Triple(&'r [u8], &'r [u8], &'r [u8]),
}

impl<'r> ByteSlices<'r> {
    /// Len of the slices
    #[inline]
    pub fn len(&'r self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Double(_, _) => 2,
            Self::Triple(_, _, _) => 3,
        }
    }
    /// Total len of all the slices combined
    #[inline]
    pub fn total_len(&'r self) -> usize {
        match self {
            Self::Single(x) => x.len(),
            Self::Double(x, y) => x.len() + y.len(),
            Self::Triple(x, y, z) => x.len() + y.len() + z.len(),
        }
    }
    /// Iter
    #[inline]
    pub fn iter(&'r self) -> ByteSlicesIter<'r> {
        ByteSlicesIter { b: self, cur: 0 }
    }
}

pub struct ByteSlicesIter<'r> {
    cur: usize,
    b: &'r ByteSlices<'r>,
}

impl<'r> Iterator for ByteSlicesIter<'r> {
    type Item = &'r [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let r = match self.b {
            ByteSlices::Single(x) => match self.cur {
                0 => Some(x),
                _ => None,
            },
            ByteSlices::Double(x, y) => match self.cur {
                0 => Some(x),
                1 => Some(y),
                _ => None,
            },
            ByteSlices::Triple(x, y, z) => match self.cur {
                0 => Some(x),
                1 => Some(y),
                2 => Some(z),
                _ => None,
            },
        };
        if r.is_some() {
            self.cur += 1;
        };
        r.map(|v| &**v)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single() {
        let x: [u8; 2] = [42, 69];
        let bs = ByteSlices::Single(&x);
        assert_eq!(bs.len(), 1);
        assert_eq!(bs.total_len(), 2);
    }

    #[test]
    fn single_iter() {
        let x: [u8; 2] = [42, 69];
        let bs = ByteSlices::Single(&x);
        let mut i = bs.iter();
        assert_eq!(i.next(), Some(x.as_ref()));
        assert_eq!(i.next(), None);
    }    

    #[test]
    fn double() {
        let x: [u8; 2] = [42, 69];
        let y: [u8; 2] = [70, 71];
        let bs = ByteSlices::Double(&x, &y);
        assert_eq!(bs.len(), 2);
        assert_eq!(bs.total_len(), 4);
    }

    #[test]
    fn double_iter() {
        let x: [u8; 2] = [42, 69];
        let y: [u8; 2] = [70, 71];
        let bs = ByteSlices::Double(&x, &y);
        let mut i = bs.iter();
        assert_eq!(i.next(), Some(x.as_ref()));
        assert_eq!(i.next(), Some(y.as_ref()));
        assert_eq!(i.next(), None);
    }    

    #[test]
    fn triple() {
        let x: [u8; 2] = [42, 69];
        let y: [u8; 2] = [70, 71];
        let z: [u8; 2] = [72, 73];        
        let bs = ByteSlices::Triple(&x, &y, &z);
        assert_eq!(bs.len(), 3);
        assert_eq!(bs.total_len(), 6);
    }

    #[test]
    fn triple_iter() {
        let x: [u8; 2] = [42, 69];
        let y: [u8; 2] = [70, 71];
        let z: [u8; 2] = [72, 73];        
        let bs = ByteSlices::Triple(&x, &y, &z);
        let mut i = bs.iter();

        assert_eq!(i.next(), Some(x.as_ref()));
        assert_eq!(i.next(), Some(y.as_ref()));
        assert_eq!(i.next(), Some(z.as_ref()));
        assert_eq!(i.next(), None);
    }        
    
}
