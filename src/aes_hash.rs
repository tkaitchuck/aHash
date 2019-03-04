use crate::convert::Convert;
use std::default::Default;
use std::hash::{Hasher};
use std::mem::transmute;

use const_random::const_random;

//This file contains the AES speffic hash implementation extracted so that it can be tested independently
//Nothing here is exported.

const DEFAULT_KEYS: [u64;2] = [const_random!(u64), const_random!(u64)];

impl Default for AesHasher {
    #[inline]
    fn default() -> AesHasher {
        AesHasher { buffer: DEFAULT_KEYS }
    }
}

impl AesHasher {
    pub fn new_with_keys(key0: u64, key1: u64) -> AesHasher {
        AesHasher { buffer: [key0, key1] }
    }
}

#[derive(Debug, Clone)]
pub struct AesHasher {
    buffer: [u64; 2],
}

/// Provides methods to hash all of the primitive types.
impl Hasher for AesHasher {
    //Implementation note: each of the write_XX methods passes the arguments slightly differently to hash.
    //This is done so that an u8 and a u64 that both contain the same value will produce different hashes.
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.buffer = hash([self.buffer[1], self.buffer[0] ^ i as u64].convert(), self.buffer.convert()).convert();
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.buffer = hash([self.buffer[1] ^ i as u64, self.buffer[0]].convert(), self.buffer.convert()).convert();
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.buffer = hash([self.buffer[0], self.buffer[1] ^ i as u64].convert(), self.buffer.convert()).convert();
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        let buffer: u128 = self.buffer.convert();
        self.buffer = hash((buffer ^ i).convert(), self.buffer.convert()).convert();
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.buffer = hash([self.buffer[0] ^ i, self.buffer[1]].convert(), self.buffer.convert()).convert();
    }
    #[inline]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        let mut remainder_low: u64 = self.buffer[0];
        let mut remainder_hi: u64 = self.buffer[1];
        if data.len() >= 16 {
            while data.len() >= 16 {
                let (block, rest) = data.split_at(16);
                let block: &[u8; 16] = as_array!(block, 16);
                self.buffer = hash(self.buffer.convert(), *block).convert();
                data = rest;
            }
            //This is to hash the final block read in the loop. Note the argument order to hash in the loop.
            self.buffer = hash(self.buffer.convert(), self.buffer.convert()).convert();
        }
        if data.len() >= 8 {
            let (block, rest) = data.split_at(8);
            let val: u64 = as_array!(block, 8).convert();
            remainder_hi ^= val;
            // This rotate is done to prevent someone from creating a collision by adding 8 nulls to a value.
            remainder_hi = remainder_hi.rotate_left(32);
            data = rest;
        }
        if data.len() >= 4 {
            let (block, rest) = data.split_at(4);
            let val: u32 = as_array!(block, 4).convert();
            remainder_low ^= val as u64;
            remainder_low = remainder_low.rotate_left(32);
            data = rest;
        }
        if data.len() >= 2 {
            let (block, rest) = data.split_at(2);
            let val: u16 = as_array!(block, 2).convert();
            remainder_low ^= val as u64;
            remainder_low = remainder_low.rotate_left(16);
            data = rest;
        }
        if data.len() >= 1 {
            remainder_low ^= data[0] as u64;
            remainder_low = remainder_low.rotate_left(8);
        }
        self.buffer = hash([remainder_low, remainder_hi].convert(), self.buffer.convert()).convert();
    }
    #[inline]
    fn finish(&self) -> u64 {
        let result: [u64; 2] = hash(self.buffer.convert(), self.buffer.convert()).convert();
        result[0]//.wrapping_add(result[1])
    }
}

#[inline(always)]
fn hash(value: [u8; 16], xor: [u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;
    unsafe {
        let value = transmute(value);
        transmute(_mm_aesenc_si128(value, transmute(xor)))
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::hash::{BuildHasherDefault};
    use crate::convert::Convert;
    use crate::aes_hash::*;

    #[test]
    fn test_builder() {
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AesHasher>>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_default() {
        let hasher_a = AesHasher::default();
        assert_ne!(0, hasher_a.buffer[0]);
        assert_ne!(0, hasher_a.buffer[1]);
        assert_ne!(hasher_a.buffer[0], hasher_a.buffer[1]);
        let hasher_b = AesHasher::default();
        assert_eq!(hasher_a.buffer[0], hasher_b.buffer[0]);
        assert_eq!(hasher_a.buffer[1], hasher_b.buffer[1]);
    }

    #[test]
    fn test_hash() {
        let mut result: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value: [u64; 2] = [1 << 32, 0xFEDCBA9876543210];
        result = hash(value.convert(), result.convert()).convert();
        result = hash(result.convert(), result.convert()).convert();
        let mut result2: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value2: [u64; 2] = [1, 0xFEDCBA9876543210];
        result2 = hash(value2.convert(), result2.convert()).convert();
        result2 = hash(result2.convert(), result.convert()).convert();
        let result: [u8; 16] = result.convert();
        let result2: [u8; 16] = result2.convert();
        assert_ne!(hex::encode(result), hex::encode(result2));
    }

    #[test]
    fn test_conversion() {
        let input: &[u8] = "dddddddd".as_bytes();
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }
}
