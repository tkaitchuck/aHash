mod convert;

///# aHash
///
/// This hashing algorithm is intended to be a DOS resistant, hardware specific, alternative to FxHash.
/// It provides a high speed hash algorithm, but unlike FxHash it is a Keyed hash. This allows it to be used
/// in a HashMap without allowing for the possibility that an malicious user can induce a collision.
///
/// # How aHash works
///
/// aHash uses the hardware AES instruction on x86 processors to provide a keyed hash function.
/// It uses two rounds of AES per hash. So it should not be considered cryptographically secure.

use crate::convert::Convert;
use std::collections::{HashMap};
use std::collections::hash_map::RandomState;
use std::default::Default;
use std::hash::{BuildHasherDefault, Hasher};
use std::mem::transmute;

/// A builder for an AHasher that uses a thread local random number to generate the keys.
/// To controll the keys uses instead call [AHasher](struct.AHasher.html#method.new_with_keys)
pub type ABuildHasher = BuildHasherDefault<AHasher>;

/// A `HashMap` using a default aHash hasher.
pub type AHashMap<K, V> = HashMap<K, V, ABuildHasher>;

//const DEFAULT_KEYS: [u64; 2] = [0x6c62_272e_07bb_0142, 0x517c_c1b7_2722_0a95];

#[derive(Debug, Clone)]
pub struct AHasher {
    buffer: [u64; 2],
}

impl AHasher {
    pub fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer:[key0, key1] }
    }
}

impl Default for AHasher {
    /// Copied from `std/collections/hash/RandomState`
    /// TODO figure out how to refer to it so as to not duplicate code.
    #[inline]
    fn default() -> AHasher {
        thread_local!(static KEYS: Cell<(u64, u64)> = {
            Cell::new(sys::hashmap_random_keys())
        });

        KEYS.with(|keys| {
            let (k0, k1) = keys.get();
            keys.set((k0.wrapping_add(1), k1));
            AHasher { buffer: [k0, k1] }
        })
    }
}

macro_rules! as_array {
    ($input:expr, $len:expr) => {{
        {
            #[inline]
            fn as_array<T>(slice: &[T]) -> &[T; $len] {
                assert_eq!(slice.len(), $len);
                unsafe {
                    &*(slice.as_ptr() as *const [_; $len])
                }
            }
            as_array($input)
        }
    }}
}

//Note that each of the write_XX methods passes the arguments slightly differently to hash.
//This is done so that an u8 and a u64 that both contain the same value will produce different hashes.
impl Hasher for AHasher {
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
        self.buffer = hash([self.buffer[0], self.buffer[1]  ^ i as u64].convert(), self.buffer.convert()).convert();
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
            self.buffer = hash(self.buffer.convert(), self.buffer.convert()).convert();
        }
        if data.len() >= 8 {
            let (block, rest) = data.split_at(8);
            let val: u64 = as_array!(block, 8).convert();
            remainder_hi ^= val;
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

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes"
))]
#[cfg(test)]
mod tests {
    use crate::convert::Convert;
    use crate::*;
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
