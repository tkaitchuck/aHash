const BAD_KEY: u64 = 0x5252_5252_5252_5252; //This encrypts to 0.

///Basic sanity tests of the cypto properties of aHash.
#[cfg(test)]
mod aes_tests {
    use std::hash::{Hash, Hasher};
    use crate::aes_hash::*;
    use crate::hash_quality_test::*;

    pub fn ahash<H: Hash>(b: H) -> u64 {
        let mut hasher = AesHasher::new_with_keys(BAD_KEY, BAD_KEY);
        b.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_single_bit_in_byte() {
        let mut hasher1= AesHasher::new_with_keys(64, 64);
        8_u32.hash(&mut hasher1);
        let mut hasher2= AesHasher::new_with_keys(64, 64);
        0_u32.hash(&mut hasher2);
        assert_sufficiently_different(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_single_bit_flip() {
        let size = 32;
        let compare_value = ahash(0u32);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u32 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
        let size = 64;
        let compare_value = ahash(0u64);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u64 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
        let size = 128;
        let compare_value = ahash(0u128);
        for pos in 0..size {
            let test_value = ahash(0 ^ (1u128 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
    }

    #[test]
    fn test_keys_change_output() {
        let mut a = AesHasher::new_with_keys(0, 0);
        let mut b = AesHasher::new_with_keys(0, 1);
        let mut c = AesHasher::new_with_keys(1, 0);
        let mut d = AesHasher::new_with_keys(1, 1);
        "test".hash(&mut a);
        "test".hash(&mut b);
        "test".hash(&mut c);
        "test".hash(&mut d);
        assert_sufficiently_different(a.finish(), b.finish());
        assert_sufficiently_different(a.finish(), c.finish());
        assert_sufficiently_different(a.finish(), d.finish());
        assert_sufficiently_different(b.finish(), c.finish());
        assert_sufficiently_different(b.finish(), d.finish());
        assert_sufficiently_different(c.finish(), d.finish());
    }

    #[test]
    fn test_finish_is_consistant() {
        let mut hasher = AesHasher::new_with_keys(1, 2);
        "Foo".hash(&mut hasher);
        let a = hasher.finish();
        let b = hasher.finish();
        assert_eq!(a, b);
    }

    #[test]
    fn test_single_key_bit_flip() {
        for bit in 0..64 {
            let mut a = AesHasher::new_with_keys(0, 0);
            let mut b = AesHasher::new_with_keys(0, 1 << bit);
            let mut c = AesHasher::new_with_keys(1 << bit, 0);
            "1234".hash(&mut a);
            "1234".hash(&mut b);
            "1234".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
            let mut a = AesHasher::new_with_keys(0, 0);
            let mut b = AesHasher::new_with_keys(0, 1 << bit);
            let mut c = AesHasher::new_with_keys(1 << bit, 0);
            "12345678".hash(&mut a);
            "12345678".hash(&mut b);
            "12345678".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
            let mut a = AesHasher::new_with_keys(0, 0);
            let mut b = AesHasher::new_with_keys(0, 1 << bit);
            let mut c = AesHasher::new_with_keys(1 << bit, 0);
            "1234567812345678".hash(&mut a);
            "1234567812345678".hash(&mut b);
            "1234567812345678".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
        }
    }

    #[test]
    fn test_padding_doesnot_collide() {
        for c in 0..128u8 {
            for string in ["", "1234", "12345678", "1234567812345678"].into_iter() {
                let mut short = AesHasher::default();
                string.hash(&mut short);
                let value = short.finish();
                let mut string = string.to_string();
                for num in 1..=128 {
                    let mut long = AesHasher::default();
                    string.push(c as char);
                    string.hash(&mut long);
                    let same_bytes = count_same_bytes(value, long.finish());
                    assert!(same_bytes <= 2, format!("{} bytes of {} -> {:x} vs {:x}", num, c, value, long.finish()));
                    let flipped_bits = (value ^ long.finish()).count_ones();
                    assert!(flipped_bits > 10);
                }
            }
        }
    }
}

fn assert_sufficiently_different(a: u64, b: u64) {
    let same_byte_count = count_same_bytes(a, b);
    assert!(same_byte_count <= 1);
    let flipped_bits = (a ^ b).count_ones();
    assert!(flipped_bits > 18 && flipped_bits < 48, "{:x} and {:x}: {:}", a, b, flipped_bits);
    for rotate in 0..64 {
        let flipped_bits2 = (a ^ (b.rotate_left(rotate))).count_ones();
        assert!(flipped_bits2 > 14 && flipped_bits2 < 50, "{:x} and {:x}: {:}", a, b.rotate_left(rotate), flipped_bits2);
    }
}

fn count_same_bytes(a: u64, b: u64) -> i32 {
    let mut same_byte_count = 0;
    for byte in 0..8 {
        let ba = a >> 8 * byte as u8;
        let bb = b >> 8 * byte as u8;
        if ba == bb {
            same_byte_count += 1;
        }
    }
    same_byte_count
}


#[cfg(test)]
mod fallback_tests {
    use std::hash::{Hash, Hasher};
    use crate::fallback_hash::*;
    use crate::hash_quality_test::*;

    pub fn fallback<H: Hash>(b: H) -> u64 {
        let mut hasher = FallbackHasher::new_with_keys(BAD_KEY, BAD_KEY);
        b.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_single_bit_flip() {
        let size = 32;
        let compare_value = fallback(0u32);
        for pos in 0..size {
            let test_value = fallback(0 ^ (1u32 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
        let size = 64;
        let compare_value = fallback(0u64);
        for pos in 0..size {
            let test_value = fallback(0 ^ (1u64 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
        let size = 128;
        let compare_value = fallback(0u128);
        for pos in 0..size {
            let test_value = fallback(0 ^ (1u128 << pos));
            assert_sufficiently_different(compare_value, test_value);
        }
    }

    #[test]
    fn test_keys_change_output() {
        let mut a = FallbackHasher::new_with_keys(0, 0);
        let mut b = FallbackHasher::new_with_keys(0, 1);
        let mut c = FallbackHasher::new_with_keys(1, 0);
        let mut d = FallbackHasher::new_with_keys(1, 1);
        "test".hash(&mut a);
        "test".hash(&mut b);
        "test".hash(&mut c);
        "test".hash(&mut d);
        assert_sufficiently_different(a.finish(), b.finish());
        assert_sufficiently_different(a.finish(), c.finish());
        assert_sufficiently_different(a.finish(), d.finish());
        assert_sufficiently_different(b.finish(), c.finish());
        assert_sufficiently_different(b.finish(), d.finish());
        assert_sufficiently_different(c.finish(), d.finish());
    }

    #[test]
    fn test_finish_is_consistant() {
        let mut hasher = FallbackHasher::new_with_keys(1, 2);
        "Foo".hash(&mut hasher);
        let a = hasher.finish();
        let b = hasher.finish();
        assert_eq!(a, b);
    }

    #[test]
    fn test_single_key_bit_flip() {
        for bit in 0..64 {
            let mut a = FallbackHasher::new_with_keys(0, 0);
            let mut b = FallbackHasher::new_with_keys(0, 1 << bit);
            let mut c = FallbackHasher::new_with_keys(1 << bit, 0);
            "1234".hash(&mut a);
            "1234".hash(&mut b);
            "1234".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
            let mut a = FallbackHasher::new_with_keys(0, 0);
            let mut b = FallbackHasher::new_with_keys(0, 1 << bit);
            let mut c = FallbackHasher::new_with_keys(1 << bit, 0);
            "12345678".hash(&mut a);
            "12345678".hash(&mut b);
            "12345678".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
            let mut a = FallbackHasher::new_with_keys(0, 0);
            let mut b = FallbackHasher::new_with_keys(0, 1 << bit);
            let mut c = FallbackHasher::new_with_keys(1 << bit, 0);
            "1234567812345678".hash(&mut a);
            "1234567812345678".hash(&mut b);
            "1234567812345678".hash(&mut c);
            assert_sufficiently_different(a.finish(), b.finish());
            assert_sufficiently_different(a.finish(), c.finish());
            assert_sufficiently_different(b.finish(), c.finish());
        }
    }

    #[test]
    fn test_padding_doesnot_collide() {
        for c in 0..128u8 {
            for string in ["", "1234", "12345678", "1234567812345678"].into_iter() {
                let mut short = FallbackHasher::new_with_keys(BAD_KEY, BAD_KEY);
                string.hash(&mut short);
                let value = short.finish();
                let mut string = string.to_string();
                for num in 1..=128 {
                    let mut long = FallbackHasher::new_with_keys(BAD_KEY, BAD_KEY);
                    string.push(c as char);
                    string.hash(&mut long);
                    let same_bytes = count_same_bytes(value, long.finish());
                    assert!(same_bytes <= 2, format!("{} bytes of {} -> {:x} vs {:x}", num, c, value, long.finish()));
                    let flipped_bits = (value ^ long.finish()).count_ones();
                    assert!(flipped_bits > 10,
                            format!("Too few bits fliped {} -> {:x} vs {} -> {:x}", string, value, c, long.finish()));
                }
            }
        }
    }
}