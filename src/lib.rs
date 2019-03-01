mod convert;

///# aHash
///
/// This hashing algorithm is intended to be a DOS resistant, hardware specific, Hash.
/// This can be seen as a DOS resistant alternative to FxHash, or a fast equivalent to SipHash.
/// It provides a high speed hash algorithm, and is a Keyed hash. This allows it to be used
/// in a HashMap without allowing for the possibility that an malicious user can induce a collision.
///
/// # How aHash works
///
/// aHash uses the hardware AES instruction on x86 processors to provide a keyed hash function.
/// It uses two rounds of AES per hash. So it should not be considered cryptographically secure.

use crate::convert::Convert;
use std::collections::{HashMap};
use std::default::Default;
use std::hash::{BuildHasherDefault, Hasher, BuildHasher};
use std::mem::transmute;

/// A `HashMap` using a `LocationBasedState` BuildHasher to hash the items.
pub type AHashMap<K, V> = HashMap<K, V, LocationBasedState>;

const DEFAULT_KEYS: [u64; 2] = [0x6c62_272e_07bb_0142, 0x517c_c1b7_2722_0a95];

/// Provides a `BuildHasher` is typically used (e.g. by [`HashMap`]) to create
/// [`AHasher`]s for each key such that they are hashed independently of one
/// another, since [`AHasher`]s contain state.
///
/// LocationBasedState uses it's in-memory location to see the AHasher. This
/// is more predictable than true random values, but does not require generating
/// them.
///
/// For each instance of `LocationBasedState`, the [`AHasher`]s created by
/// [`build_hasher`] should be identical. That is, if the same stream of bytes
/// is fed into each hasher, the same output will also be generated.
///
/// # Examples
///
/// ```
/// use ahash::LocationBasedState;
/// use std::hash::{BuildHasher, Hasher};
///
/// let s = LocationBasedState::new();
/// let mut hasher_1 = s.build_hasher();
/// let mut hasher_2 = s.build_hasher();
///
/// hasher_1.write_u32(8128);
/// hasher_2.write_u32(8128);
///
/// assert_eq!(hasher_1.finish(), hasher_2.finish());
/// ```
///
/// [`build_hasher`]: #tymethod.build_hasher
/// [`Hasher`]: trait.Hasher.html
/// [`HashMap`]: ../../std/collections/struct.HashMap.html
pub struct LocationBasedState { }

impl LocationBasedState {
    pub fn new() -> LocationBasedState {
        LocationBasedState{}
    }
}
impl BuildHasher for LocationBasedState {
    type Hasher = AHasher;

    fn build_hasher(&self) -> AHasher {
        let location = self as *const Self as u64;
        AHasher {buffer:[location, location.rotate_left(8)]}
    }
}
impl Default for LocationBasedState {
    fn default() -> LocationBasedState {
        LocationBasedState{}
    }
}

/// A `Hasher` for hashing an arbitrary stream of bytes.
///
/// Instances of `AHasher` represent state that is updated while hashing data.
///
/// Each method updates the internal state based on the new data provided. Once
/// all of the data has been provided, the resulting hash can be obtained by calling
/// `finish()`
///
/// #Example
///
/// ```
/// use std::hash::Hasher;
/// use ahash::AHasher;
///
/// let mut hasher = AHasher::new_with_keys(123, 456);
///
/// hasher.write_u32(1989);
/// hasher.write_u8(11);
/// hasher.write_u8(9);
/// hasher.write(b"Huh?");
///
/// println!("Hash is {:x}!", hasher.finish());
/// ```
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
    #[inline]
    fn default() -> AHasher {
        AHasher { buffer: [DEFAULT_KEYS[0], DEFAULT_KEYS[1]] }
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

//Implementation note: each of the write_XX methods passes the arguments slightly differently to hash.
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
    fn test_builder() {
        let mut map = HashMap::<u32, u64, LocationBasedState>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_location_based_state() {
        let state = LocationBasedState::new();
        let hasher_a = state.build_hasher();
        assert_ne!(0, hasher_a.buffer[0]);
        assert_ne!(0, hasher_a.buffer[1]);
        assert_ne!(hasher_a.buffer[0], AHasher::default().buffer[0]);
        assert_ne!(hasher_a.buffer[1], AHasher::default().buffer[1]);
        let hasher_b = state.build_hasher();
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
