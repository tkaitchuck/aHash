//! # aHash
//!
//! This hashing algorithm is intended to be a high performance, (hardware specific), keyed hash function.
//! This can be seen as a DOS resistant alternative to FxHash, or a fast equivalent to SipHash.
//! It provides a high speed hash algorithm, but where the result is not predictable without knowing a Key.
//! This allows it to be used in a HashMap without allowing for the possibility that an malicious user can
//! induce a collision.
//!
//! # How aHash works
//!
//! aHash uses the hardware AES instruction on x86 processors to provide a keyed hash function.
//! It uses two rounds of AES per hash. So it should not be considered cryptographically secure.
extern crate const_random;

#[macro_use]
mod convert;

#[cfg(test)]
mod fallback_hash;
#[cfg(test)]
mod aes_hash;
#[cfg(test)]
mod hash_quality_test;

use std::collections::HashMap;
use crate::convert::Convert;
use std::default::Default;
use std::hash::{BuildHasherDefault, Hasher};

use const_random::const_random;

/// A `HashMap` using a `BuildHasherDefault` BuildHasher to hash the items.
pub type AHashMap<K, V> = HashMap<K, V, BuildHasherDefault<AHasher>>;

const DEFAULT_KEYS: [u64; 2] = [const_random!(u64), const_random!(u64)];
const PAD : u128 = 0xF0E1D2C3B4A5968778695A4B3C2D1E0F;

/// A `Hasher` for hashing an arbitrary stream of bytes.
///
/// Instances of [AHasher] represent state that is updated while hashing data.
///
/// Each method updates the internal state based on the new data provided. Once
/// all of the data has been provided, the resulting hash can be obtained by calling
/// `finish()`
///
/// [Clone] is also provided in case you wish to calculate hashes for two different items that
/// start with the same data.
///
#[derive(Debug, Clone)]
pub struct AHasher {
    buffer: [u64; 2],
}

/// Provides a [Hasher] is typically used (e.g. by [HashMap]) to create
/// [AHasher]s for each key such that they are hashed independently of one
/// another, since [AHasher]s contain state.
///
/// Constructs a new [AHasher] with compile time generated constants keys.
/// So the key will be the same from one instance to another,
/// but different from build to the next. So if it is possible for a potential
/// attacker to have access to your compiled binary it would be better
/// to specify keys generated at runtime.
///
/// # Examples
///
/// ```
/// use ahash::AHasher;
/// use std::hash::Hasher;
///
/// let mut hasher_1 = AHasher::default();
/// let mut hasher_2 = AHasher::default();
///
/// hasher_1.write_u32(8128);
/// hasher_2.write_u32(8128);
///
/// assert_eq!(hasher_1.finish(), hasher_2.finish());
/// ```
/// [Hasher]: std::hash::Hasher
/// [HashMap]: std::collections::HashMap
impl Default for AHasher {
    #[inline]
    fn default() -> AHasher {
        AHasher { buffer: DEFAULT_KEYS }
    }
}

impl AHasher {
    /// Creates a new hasher keyed to the provided keys.
    /// # Example
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
    pub fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer: [key0, key1] }
    }
}


/// Provides methods to hash all of the primitive types. using the AES instruction.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
impl Hasher for AHasher {
    //Implementation note: each of the write_XX methods passes the arguments slightly differently to hash.
    //This is done so that an u8 and a u64 that both contain the same value will produce different hashes.
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

//This value is pulled from a 64 bit LCG.
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
const MULTIPLE: u64 = 6364136223846793005;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
#[inline(always)]
fn fallbackhash(data: u64, key: u64) -> u64 {
    return (data.wrapping_mul(MULTIPLE).rotate_left(22) ^ key).wrapping_mul(MULTIPLE)
}

/// Provides methods to hash all of the primitive types. (this version doesn't depend on AES)
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
impl Hasher for AHasher {
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.buffer[0] = fallbackhash(self.buffer[0] ^ i as u64, self.buffer[1]);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.buffer[0] = fallbackhash(self.buffer[0] ^ i as u64, self.buffer[1]);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.buffer[0] = fallbackhash(self.buffer[0] ^ i as u64, self.buffer[1]);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.buffer[0] = fallbackhash(self.buffer[0] ^ i, self.buffer[1]);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        let data: [u64; 2] = i.convert();
        self.buffer[0] = fallbackhash(self.buffer[0] ^ data[0], self.buffer[1]);
        self.buffer[0] = fallbackhash(self.buffer[0] ^ data[1], self.buffer[1]);
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
            self.buffer[0] = fallbackhash(self.buffer[0] ^ val, self.buffer[1]);
            data = rest;
        }
        if data.len() >= 4 {
            let (block, rest) = data.split_at(4);
            let val: u32 = as_array!(block, 4).convert();
            self.buffer[0] ^= val as u64;
            self.buffer[0] = self.buffer[0].rotate_left(32);
            data = rest;
        }
        if data.len() >= 2 {
            let (block, rest) = data.split_at(2);
            let val: u16 = as_array!(block, 2).convert();
            self.buffer[0] ^= val as u64;
            self.buffer[0] = self.buffer[0].rotate_left(16);
            data = rest;
        }
        if data.len() >= 1 {
            self.buffer[0] ^= data[0] as u64;
            self.buffer[0] = self.buffer[0].rotate_left(8);
        }
        self.buffer[0] = fallbackhash(self.buffer[0],self.buffer[1]);
    }
    #[inline]
    fn finish(&self) -> u64 {
        fallbackhash(self.buffer[0], self.buffer[1])
    }
}

#[cfg(test)]
mod test {
    use crate::convert::Convert;
    use crate::*;

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
    fn test_conversion() {
        let input: &[u8] = "dddddddd".as_bytes();
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }
}
