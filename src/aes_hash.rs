use crate::convert::*;
use std::hash::{Hasher};
use std::intrinsics::assume;

///Just a simple bit pattern.
const PAD : u128 = 0xF0E1_D2C3_B4A5_9687_7869_5A4B_3C2D_1E0F;

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
    #[inline]
    pub(crate) fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer: [key0, key1] }
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
        //This will be scrambled by the first AES round in any branch.
        self.buffer[1] ^= length;
        //A 'binary search' on sizes reduces the number of comparisons.
        if data.len() > 8 {
            if data.len() > 32 {
                if data.len() > 64 {
                    let mut par_block: u128 = self.buffer.convert();
                    while data.len() > 64 {
                        let (b1, rest) = data.read_u128();
                        par_block = aeshash(par_block, b1);
                        data = rest;
                        let (b2, rest) = data.read_u128();
                        self.buffer = aeshash(self.buffer.convert(), b2).convert();
                        data = rest;
                    }
                    self.buffer = aeshash(self.buffer.convert(), par_block).convert();
                }
                //len 33-64
                let (first, second) = data.split_at(data.len()/2);
                unsafe{assume(first.len() >= 16)}
                unsafe{assume(second.len() >= 16)}
                self.buffer = aeshash(self.buffer.convert(), first.read_u128().0).convert();
                self.buffer = aeshash(self.buffer.convert(), first.read_last_u128()).convert();
                self.buffer = aeshash(self.buffer.convert(), second.read_u128().0).convert();
                self.buffer = aeshash(self.buffer.convert(), second.read_last_u128()).convert();
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
        } else {
            if data.len() >= 2 {
                if data.len() >= 4 {
                    //len 4-8
                    self.buffer = aeshash(self.buffer.convert(),data.read_u32().0 as u128).convert();
                    self.buffer = aeshash(self.buffer.convert(),data.read_last_u32() as u128).convert();
                } else {
                    //len 2-3
                    self.buffer = aeshash(self.buffer.convert(),data.read_u16().0 as u128).convert();
                    self.buffer = aeshash(self.buffer.convert(),data.read_last_u16() as u128).convert();
                }
            } else {
                if data.len() > 0 {
                    //len 1
                    self.buffer = aeshash(self.buffer.convert(), data[0] as u128).convert();
                }
            }
        }
    }
    #[inline]
    fn finish(&self) -> u64 {
        let result: [u64; 2] = aeshash(aeshash(self.buffer.convert(), PAD), PAD).convert();
        result[0]//.wrapping_add(result[1])
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
