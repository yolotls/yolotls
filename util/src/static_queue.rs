/// Statically defined fixed size "queue" of T
/// bounded by queue max size S
pub struct StaticQueue<T, const S: usize> {
    pub q: [Option<T>; S],
}

impl<T, const S: usize> StaticQueue<T, S> {
    /// Push T to queue returning true if added or false if beyond capacity
    #[inline]
    pub fn push(&mut self, item: T) -> bool {
        match self.q.iter().position(|i| i.is_none()) {
            Some(i) => self.q[i] = Some(item),
            None => return false,
        }
        true
    }
    /// Pop an item from quuee
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        let i = match self.q.iter().position(|i| i.is_some()) {
            Some(i) => i,
            None => return None,
        };
        let mut r = None;
        core::mem::swap(&mut r, &mut self.q[i]);
        r
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn static_queue_play() {
        let mut q = StaticQueue::<&[u8], 8> { q: [None; 8] };

        assert_eq!(q.pop(), None);
        assert_eq!(q.push(&[1, 2]), true);
        assert_eq!(q.push(&[3, 4]), true);
        assert_eq!(q.push(&[5, 6]), true);
        assert_eq!(q.push(&[7, 8]), true);
        assert_eq!(q.push(&[9, 10]), true);
        assert_eq!(q.push(&[11, 12]), true);
        assert_eq!(q.push(&[13, 14]), true);
        assert_eq!(q.push(&[15, 16]), true);
        assert_eq!(q.push(&[42, 42]), false);
        assert_eq!(q.pop(), Some([1_u8, 2_u8].as_ref()));
        assert_eq!(q.pop(), Some([3_u8, 4_u8].as_ref()));
        assert_eq!(q.pop(), Some([5_u8, 6_u8].as_ref()));
        assert_eq!(q.pop(), Some([7_u8, 8_u8].as_ref()));
        assert_eq!(q.pop(), Some([9_u8, 10_u8].as_ref()));
        assert_eq!(q.pop(), Some([11_u8, 12_u8].as_ref()));
        assert_eq!(q.pop(), Some([13_u8, 14_u8].as_ref()));
        assert_eq!(q.pop(), Some([15_u8, 16_u8].as_ref()));
        assert_eq!(q.pop(), None);
        assert_eq!(q.push(&[69, 69]), true);
        assert_eq!(q.pop(), Some([69u8, 69u8].as_ref()));
        assert_eq!(q.pop(), None);
    }
}
