use crate::convert::{Convert};
use std::hash::{Hasher};
use const_random::const_random;

//This file contains the fallback hasher separated so it can be tested independently.
//Nothing here is exported.

//This value is pulled from a 64 bit LCG.
const MULTIPLE: u64 = 6364136223846793005;

const DEFAULT_KEYS: [u64; 2] = [const_random!(u64), const_random!(u64)];

#[derive(Debug, Clone)]
pub struct AHasher {
    buffer: u64,
    key: u64,
}

impl AHasher {
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer: key0, key: key1 }
    }
}
impl Default for AHasher {
    #[inline]
    fn default() -> AHasher {
        AHasher {buffer: DEFAULT_KEYS[0], key: DEFAULT_KEYS[1]}
    }
}

#[inline(always)]
fn hash(data: u64, key: u64) -> u64 {
    return (data.wrapping_mul(MULTIPLE).rotate_left(22) ^ key).wrapping_mul(MULTIPLE)
}

/// Provides methods to hash all of the primitive types.
impl Hasher for AHasher {

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.buffer = hash(self.buffer ^ i as u64, self.key);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.buffer = hash(self.buffer ^ i as u64, self.key);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.buffer = hash(self.buffer ^ i as u64, self.key);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.buffer = hash(self.buffer ^ i, self.key);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        let data: [u64;2] = i.convert();
        self.buffer = hash(self.buffer ^ data[0], self.key);
        self.buffer = hash(self.buffer ^ data[1], self.key);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        while data.len() >= 8 {
            let (block, rest) = data.split_at(8);
            let val: u64 = as_array!(block, 8).convert();
            self.buffer = hash(self.buffer ^ val, self.key);
            data = rest;
        }
        if data.len() >= 4 {
            let (block, rest) = data.split_at(4);
            let val: u32 = as_array!(block, 4).convert();
            self.buffer ^= val as u64;
            self.buffer = self.buffer.rotate_left(32);
            data = rest;
        }
        if data.len() >= 2 {
            let (block, rest) = data.split_at(2);
            let val: u16 = as_array!(block, 2).convert();
            self.buffer ^= val as u64;
            self.buffer = self.buffer.rotate_left(16);
            data = rest;
        }
        if data.len() >= 1 {
            self.buffer ^= data[0] as u64;
            self.buffer = self.buffer.rotate_left(8);
        }
        self.buffer = hash(self.buffer, self.key);
    }
    #[inline]
    fn finish(&self) -> u64 {
        hash(self.buffer, self.key)
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::hash::{BuildHasherDefault};
    use crate::convert::Convert;
    use crate::fallback_hash::*;

    #[test]
    fn test_builder() {
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_default() {
        let hasher_a = AHasher::default();
        assert_ne!(0, hasher_a.buffer);
        assert_ne!(0, hasher_a.key);
        assert_ne!(hasher_a.buffer, hasher_a.key);
        let hasher_b = AHasher::default();
        assert_eq!(hasher_a.buffer, hasher_b.buffer);
        assert_eq!(hasher_a.key, hasher_b.key);
    }

    #[test]
    fn test_hash() {
        let value: u64 = 1 << 32;
        let result = hash(value, 0);
        let value2: u64 = 1;
        let result2= hash(value2, 0);
        let result: [u8; 8] = result.convert();
        let result2: [u8; 8] = result2.convert();
        assert_ne!(hex::encode(result), hex::encode(result2));
    }

    #[test]
    fn test_conversion() {
        let input: &[u8] = "dddddddd".as_bytes();
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }
}