use crate::convert::*;
use core::hash::{Hasher};

/// A `Hasher` for hashing an arbitrary stream of bytes.
///
/// Instances of [`AHasher`] represent state that is updated while hashing data.
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
    key: [u64; 2],
}

impl AHasher {
    /// Creates a new hasher keyed to the provided key.
    #[inline]
    pub fn new_with_key(key: u64) -> AHasher {
        AHasher { buffer: [key, !key] }
    }

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
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> Self {
        Self { buffer: [key0, key1], key: [key1, key0]  }
    }

    #[cfg(test)]
    pub(crate) fn test_with_keys(key1: u64, key2: u64) -> AHasher {
        use crate::scramble_keys;
        let (k1, k2) = scramble_keys(key1, key2);
        AHasher { buffer: [k1, k2], key: [k2, k1] }
    }
}

#[inline(never)]
#[no_mangle]
fn hash_test_aes(input: &[u8]) -> u64 {
    let mut a = AHasher::new_with_keys(67, 87);
    a.write(input);
    a.finish()
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
        self.buffer = aeshash(self.buffer.convert(), i).convert();
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
        //This will be scrambled by the first AES round in any branch.
        self.buffer[1] = self.buffer[1].wrapping_add(length);
        //A 'binary search' on sizes reduces the number of comparisons.
        if data.len() <= 8 {
            if data.len() >= 2 {
                if data.len() >= 4 {
                    //len 4-8
                    self.buffer = aeshash(self.buffer.convert(), data.read_u32().0 as u128).convert();
                    self.buffer = aeshash(self.buffer.convert(), data.read_last_u32() as u128).convert();
                } else {
                    //len 2-3
                    self.buffer = aeshash(self.buffer.convert(), data.read_u16().0 as u128).convert();
                    self.buffer = aeshash(self.buffer.convert(), data[data.len() - 1] as u128).convert();
                }
            } else {
                let value;
                if data.len() > 0 {
                    value = data[0]; //len 1
                } else {
                    value = 0;
                }
                self.buffer = aeshash(self.buffer.convert(), value as u128).convert();
            }
        } else {
            if data.len() > 32 {
                if data.len() > 64 {
                    let (_, tail) = data.split_at(data.len() - 32);
                    let mut par_block: u128 = self.buffer.convert();
                    while data.len() > 32 {
                        let (b1, rest) = data.read_u128();
                        self.buffer = aeshash(self.buffer.convert(), b1).convert();
                        data = rest;
                        let (b2, rest) = data.read_u128();
                        par_block = aeshash(par_block, b2);
                        data = rest;
                    }
                    let (b1, rest) = tail.read_u128();
                    self.buffer = aeshash(self.buffer.convert(), b1).convert();
                    let (b2, _) = rest.read_u128();
                    par_block = aeshash(par_block, b2);
                    self.buffer = aeshash(self.buffer.convert(), par_block).convert();
                } else {
                    //len 33-64
                    let (head, _) = data.split_at(32);
                    let (_, tail) = data.split_at(data.len() - 32);
                    self.buffer = aeshash(self.buffer.convert(), head.read_u128().0).convert();
                    self.buffer = aeshash(self.buffer.convert(), head.read_last_u128()).convert();
                    self.buffer = aeshash(self.buffer.convert(), tail.read_u128().0).convert();
                    self.buffer = aeshash(self.buffer.convert(), tail.read_last_u128()).convert();
                }
            } else {
                if data.len() > 16 {
                    //len 17-32
                    self.buffer = aeshash(self.buffer.convert(), data.read_u128().0).convert();
                    self.buffer = aeshash(self.buffer.convert(), data.read_last_u128()).convert();
                } else {
                    //len 9-16
                    self.buffer = aeshash(self.buffer.convert(), data.read_u64().0 as u128).convert();
                    self.buffer = aeshash(self.buffer.convert(), data.read_last_u64() as u128).convert();
                }
            }
        }
    }
    #[inline]
    fn finish(&self) -> u64 {
        let result: [u64; 2] = aeshash(aeshash(self.buffer.convert(), self.key.convert()), self.key.convert()).convert();
        result[0] //.wrapping_add(result[1])
    }
}

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
#[inline(always)]
fn aeshash(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    use core::mem::transmute;
    unsafe {
        let value = transmute(value);
        transmute(_mm_aesdec_si128(value, transmute(xor)))
    }
}

#[cfg(test)]
mod tests {
    use crate::aes_hash::*;
    use crate::convert::Convert;
    use std::collections::HashMap;
    use std::hash::BuildHasherDefault;

    #[cfg(feature = "compile-time-rng")]
    #[test]
    fn test_builder() {
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }

    #[cfg(feature = "compile-time-rng")]
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
