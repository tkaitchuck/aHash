use ahash::*;
use std::hash::{Hash, Hasher};

///Basic sanity tests of the cypto properties of aHash. 
#[cfg(test)]
mod crypto {
    use crate::*;

    pub fn ahash<H: Hash>(b: H) -> u64 {
        let mut hasher = AHasher::new_with_keys(0, 0);
        b.hash(&mut hasher);
        hasher.finish()
    }

    fn assert_sufficently_different(a: u64, b: u64) {
        let flipped_bits = (a ^ b).count_ones();
        assert!(flipped_bits > 14 && flipped_bits < 50, "{:x} and {:x}: {:}",a, b, flipped_bits);
        for rotate in 0..64 {
            let flipped_bits = (a ^ (b.rotate_left(rotate))).count_ones();
            assert!(flipped_bits > 10 && flipped_bits < 54, "{:x} and {:x}: {:x}",a, b, flipped_bits);
        }
    }

    #[test]
    fn test_single_bit_flip() {
        let size = 32;
        let compare_value = ahash(0u32);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u32 << pos));
            assert_sufficently_different(compare_value, test_value);
        }
        let size = 64;
        let compare_value = ahash(0u64);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u64 << pos));
            assert_sufficently_different(compare_value, test_value);
        }
        let size = 128;
        let compare_value = ahash(0u128);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u128 << pos));
            assert_sufficently_different(compare_value, test_value);
        }
    }

    #[test]
    fn test_keys_change_output() {
        let mut a = AHasher::new_with_keys(0, 0);
        let mut b = AHasher::new_with_keys(0, 1);
        let mut c = AHasher::new_with_keys(1, 0);
        let mut d = AHasher::new_with_keys(1, 1);
        "test".hash(&mut a);
        "test".hash(&mut b);
        "test".hash(&mut c);
        "test".hash(&mut d);
        assert_sufficently_different(a.finish(), b.finish());
        assert_sufficently_different(a.finish(), c.finish());
        assert_sufficently_different(a.finish(), d.finish());
        assert_sufficently_different(b.finish(), c.finish());
        assert_sufficently_different(b.finish(), d.finish());
        assert_sufficently_different(c.finish(), d.finish());
    }

    #[test]
    fn test_finish_is_consistant() {
        let mut hasher = AHasher::new_with_keys(1, 2);
        "Foo".hash(&mut hasher);
        let a = hasher.finish();
        let b = hasher.finish();
        assert_eq!(a, b);
    }

    #[test]
    fn test_single_key_bit_flip() {
        for bit in 0..64 {
            let mut a = AHasher::new_with_keys(0, 0);
            let mut b = AHasher::new_with_keys(0, 1 << bit);
            let mut c = AHasher::new_with_keys(1 << bit,0);
            "1234".hash(&mut a);
            "1234".hash(&mut b);
            "1234".hash(&mut c);
            assert_sufficently_different(a.finish(), b.finish());
            assert_sufficently_different(a.finish(), c.finish());
            assert_sufficently_different(b.finish(), c.finish());
            let mut a = AHasher::new_with_keys(0, 0);
            let mut b = AHasher::new_with_keys(0, 1 << bit);
            let mut c = AHasher::new_with_keys(1 << bit,0);
            "12345678".hash(&mut a);
            "12345678".hash(&mut b);
            "12345678".hash(&mut c);
            assert_sufficently_different(a.finish(), b.finish());
            assert_sufficently_different(a.finish(), c.finish());
            assert_sufficently_different(b.finish(), c.finish());
            let mut a = AHasher::new_with_keys(0, 0);
            let mut b = AHasher::new_with_keys(0, 1 << bit);
            let mut c = AHasher::new_with_keys(1 << bit,0);
            "1234567812345678".hash(&mut a);
            "1234567812345678".hash(&mut b);
            "1234567812345678".hash(&mut c);
            assert_sufficently_different(a.finish(), b.finish());
            assert_sufficently_different(a.finish(), c.finish());
            assert_sufficently_different(b.finish(), c.finish());
        }
    }

    #[test]
    fn test_padding_doesnot_collide() {
        for c in 0..128u8 {
            for string in ["", "1234", "12345678", "1234567812345678"].into_iter() {
                let mut short = AHasher::default();
                string.hash(&mut short);
                let value= short.finish();
                let mut string = string.to_string();
                for _ in 0..128 {
                    let mut long = AHasher::default();
                    string.push(c as char);
                    string.hash(&mut long);
                    let flipped_bits = (value ^ long.finish()).count_ones();
                    assert!(flipped_bits > 10);
                }
            }
        }
    }
}