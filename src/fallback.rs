use crate::convert::{Convert};
use std::hash::{BuildHasherDefault, Hasher, BuildHasher};

//These values are not special
const DEFAULT_KEYS: [u64; 2] = [0x6c62_272e_07bb_0142, 0x517c_c1b7_2722_0a95];

//This value is pulled from a 64 bit LCG.
const MULTIPLE: u64 = 6364136223846793005;

#[derive(Debug, Clone)]
pub struct FallbackHasher {
    buffer: u64,
    key: u64,
}

impl FallbackHasher {
    #[inline(always)]
    fn hash(&self, data: u64) -> u64 {
        return (data.wrapping_mul(MULTIPLE)).swap_bytes();
    }

    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> FallbackHasher {
        FallbackHasher { buffer: key0, key: key1 }
    }
}
impl Default for FallbackHasher {
    #[inline]
    fn default() -> FallbackHasher {
        FallbackHasher {buffer: DEFAULT_KEYS[0], key: DEFAULT_KEYS[1]}
    }
}

/// Provides methods to hash all of the primitive types.
impl Hasher for FallbackHasher {

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.buffer = self.hash(self.buffer ^ i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.buffer = self.hash(self.buffer ^ i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.buffer = self.hash(self.buffer ^ i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.buffer = self.hash(self.buffer ^ i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        let data: [u64;2] = i.convert();
        self.buffer = self.hash(self.buffer ^ data[0]);
        self.buffer = self.hash(self.buffer ^ data[1]);
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
            self.buffer = self.hash(self.buffer ^ val);
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
        self.buffer = self.hash(self.buffer ^ self.key);
    }
    #[inline]
    fn finish(&self) -> u64 {
        (self.buffer ^ self.key).wrapping_mul(MULTIPLE)
    }
}
