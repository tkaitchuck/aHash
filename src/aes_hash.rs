use crate::convert::Convert;
use std::default::Default;
use std::hash::{Hasher};
use std::mem::transmute;

use const_random::const_random;

const DEFAULT_KEYS: [u64;2] = [const_random!(u64), const_random!(u64)];
const PAD : u128 = 0xF0E1D2C3B4A5968778695A4B3C2D1E0F;

#[derive(Debug, Clone)]
pub struct AHasher {
    buffer: [u64; 2],
}

impl Default for AHasher {
    #[inline]
    fn default() -> AHasher {
        AHasher { buffer: DEFAULT_KEYS }
    }
}

impl AHasher {
    pub fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer: [key0, key1] }
    }
}

/// Provides methods to hash all of the primitive types.
impl Hasher for AHasher {
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u128(i as u128);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_u128(i as u128);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u128(i as u128);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.buffer = aeshash(self.buffer.convert(),i).convert();
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.write_u128(i as u128);
    }
    #[inline]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        let length = data.len() as u64;
        while data.len() >= 16 {
            let (block, rest) = data.split_at(16);
            let block: u128 = (*as_array!(block, 16)).convert();
            self.buffer = aeshash(self.buffer.convert(),block).convert();
            data = rest;
        }
        if data.len() >= 8 {
            let (block, rest) = data.split_at(8);
            let block: u64 = (*as_array!(block, 8)).convert();
            self.buffer = aeshash(self.buffer.convert(),block as u128).convert();
            data = rest;
        }
        if data.len() >= 4 {
            let (block, rest) = data.split_at(4);
            let block: u32 = (*as_array!(block, 4)).convert();
            self.buffer = aeshash(self.buffer.convert(),block as u128).convert();
            data = rest;
        }
        if data.len() >= 2 {
            let (block, rest) = data.split_at(2);
            let block: u16 = (*as_array!(block, 2)).convert();
            self.buffer = aeshash(self.buffer.convert(), block as u128).convert();
            data = rest;
        }
        if data.len() >= 1 {
            self.buffer = aeshash(self.buffer.convert(), data[0] as u128).convert();
        }
        self.buffer = aeshash(self.buffer.convert(), [length, length].convert()).convert();
    }
    #[inline]
    fn finish(&self) -> u64 {
        let result: [u64; 2] = aeshash(aeshash(self.buffer.convert(), PAD), PAD).convert();
        result[1]//.wrapping_add(result[1])
    }
}

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
#[inline(always)]
fn aeshash(value: u128, xor: u128) -> u128 {
    use std::mem::transmute;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;
    unsafe {
        let value = transmute(value);
        transmute(_mm_aesdec_si128(value, transmute(xor)))
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
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_default() {
        let hasher_a = AHasher::default();
        assert_ne!(0, hasher_a.buffer[0]);
        assert_ne!(0, hasher_a.buffer[1]);
        assert_ne!(hasher_a.buffer[0], hasher_a.buffer[1]);
        let hasher_b = AHasher::default();
        assert_eq!(hasher_a.buffer[0], hasher_b.buffer[0]);
        assert_eq!(hasher_a.buffer[1], hasher_b.buffer[1]);
    }

    #[test]
    fn test_hash() {
        let mut result: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value: [u64; 2] = [1 << 32, 0xFEDCBA9876543210];
        result = aeshash(value.convert(), result.convert()).convert();
        result = aeshash(result.convert(), result.convert()).convert();
        let mut result2: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value2: [u64; 2] = [1, 0xFEDCBA9876543210];
        result2 = aeshash(value2.convert(), result2.convert()).convert();
        result2 = aeshash(result2.convert(), result.convert()).convert();
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
