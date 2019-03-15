use crate::convert::{Convert};
use std::hash::{Hasher};
use const_random::const_random;
use arrayref::*;

///These constants come from splitmix64 which is derived from Java's SplitableRandom, which is based on DotMix and MurmurHash3.
const MULTIPLES: [u64; 2] = [0xBF58476D1CE4E5B9, 0x94D049BB133111EB];
const INCREMENT: u64 = 0x9e3779b97f4a7c15;

///Const random provides randomzied keys with no runtime cost.
const DEFAULT_KEYS: [u64; 2] = [const_random!(u64), const_random!(u64)];

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
    buffer: u64,
    key: u64,
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
        AHasher {buffer: DEFAULT_KEYS[0], key: DEFAULT_KEYS[1]}
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
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> AHasher {
        AHasher { buffer: key0, key: key1 }
    }

    /// This update function has the goal of updating the buffer with a single multiply
    /// FxHash does this but is venerable to attack. To avoid this input needs to be masked to with an unpredictable value.
    /// However other hashes such as murmurhash have taken that approach but were found venerable to attack.
    /// The attack was based on the idea of reversing the pre-mixing (Which is necessarily reversible otherwise
    /// bits would be lost) then placing a difference in the highest bit before the multiply. Because a multiply
    /// can never affect the bits to the right of it. This version avoids this vulnerability by rotating and
    /// performing a second multiply. This makes it impossible for an attacker to place a single bit
    /// difference between two blocks so as to cancel each other. (While the transform is still reversible if you know the key)
    ///
    /// The key needs to be incremented between consecutive calls to prevent (a,b) from hashing the same as (b,a).
    /// The adding of the increment is moved to the bottom rather than the top. This allows one less add to be
    /// performed overall, but more importantly, it follows the multiply, which is expensive. So the CPU can
    /// run another operation afterwords if does not depend on the output of the multiply operation.
    ///
    /// The update of the buffer to perform the second multiply is moved from the end to the beginning of the method.
    /// This has the effect of causing the next call to update to perform he second multiply. For the final
    /// update this is performed in the finalize method. This might seem wasteful, but its actually an optimization.
    /// If the method get's inlined into the caller where it is being invoked on a single primitive, the first call
    /// to update the buffer will be operating on constants and the compiler will optimize it out, by replacing it with
    /// the result.
    #[inline(always)]
    fn update(&mut self, new_data: u64) {
        self.buffer = (self.buffer.rotate_right(27)).wrapping_mul(MULTIPLES[1]);
        self.buffer ^= (new_data ^ self.key).wrapping_mul(MULTIPLES[0]);
        self.key = self.key.wrapping_add(INCREMENT);
    }


    /// This is similar to the above update function (see it's description) but handles the second multiply
    /// directly ans xors at the end. It is structured so that the buffer is only xored into at the end.
    /// Because the method is configured to be inlined, the compiler will unroll any loop this gets placed in
    /// and the loop can be automatically vectorized and the rotates, xors, and multiplies can be paralleled.
    #[inline(always)]
    fn ordered_update(&mut self, new_data: u64) {
        let value = (new_data ^ self.key).wrapping_mul(MULTIPLES[0]);
        self.buffer ^= value.rotate_right(27).wrapping_mul(MULTIPLES[1]);
        self.key = self.key.wrapping_add(INCREMENT);
    }
}

/// Provides methods to hash all of the primitive types.
impl Hasher for AHasher {

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.update(i as u64);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        let data: [u64;2] = i.convert();
        self.update(data[0]);
        self.update(data[1]);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        let length = data.len() as u64;
        //Needs to be an add rather than an xor because otherwise it could be canceled with carefully formed input.
        self.key = self.key.wrapping_add(length);
        //A 'binary search' on sizes reduces the number of comparisons.
        if data.len() >= 8 {
            while data.len() > 16 {
                let (block, rest) = data.split_at(8);
                let val: u64 = as_array!(block, 8).convert();
                self.ordered_update(val);
                data = rest;
            }
            let val: u64 = (*array_ref!(data, 0, 8)).convert();
            self.ordered_update(val);
            let val: u64 = (*array_ref!(data, data.len()-8, 8)).convert();
            self.update(val);
        } else {
            if data.len() >= 2 {
                if data.len() >= 4 {
                    let block: [u32; 2] = [(*array_ref!(data, 0, 4)).convert(),
                        (*array_ref!(data, data.len()-4, 4)).convert()];
                    self.update(block.convert());
                } else {
                    let block: [u16; 2] = [(*array_ref!(data, 0, 2)).convert(),
                        (*array_ref!(data, data.len()-2, 2)).convert()];
                    let val: u32 = block.convert();
                    self.update(val as u64);
                }
            } else {
                if data.len() >= 1 {
                    self.update(data[0] as u64);
                }
            }
        }
    }
    #[inline]
    fn finish(&self) -> u64 {
        //This finalization logic comes from splitmix64.
        let result = self.buffer ^ self.key;
//        let result = ((result >> 30) ^ result).wrapping_mul(MULTIPLES[0]);
        let result = (result.rotate_right(27)).wrapping_mul(MULTIPLES[1]);
        result ^ (result >> 31)
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
        let mut hasher = AHasher::new_with_keys(0,0);
        let value: u64 = 1 << 32;
        hasher.update(value);
        let result = hasher.buffer;
        let mut hasher = AHasher::new_with_keys(0,0);
        let value2: u64 = 1;
        hasher.update(value2);
        let result2 = hasher.buffer;
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
