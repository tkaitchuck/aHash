use crate::convert::*;
use crate::operations::*;
use crate::random_state::PI_U128X2;
use crate::RandomState;
use core::hash::Hasher;

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
    /// A second copy of what `chain` last received, combined with `sum`.
    echo: u128,
    /// Collects what has passed through `echo`, so it never holds a value as supplied. Starts as the sum of the
    /// keys: their xor would make `with_seeds(s, s, s, s)` independent of `s`.
    sum: u128,
    /// Takes each value as it arrives.
    chain: u128,
}

impl AHasher {
    /// Creates a new hasher keyed to the provided keys.
    ///
    /// Normally hashers are created via `AHasher::default()` for fixed keys or `RandomState::new()` for randomly
    /// generated keys and `RandomState::with_seeds(a,b)` for seeds that are set and can be reused. All of these work at
    /// map creation time (and hence don't have any overhead on a per-item basis).
    ///
    /// This method directly creates the hasher instance and performs no transformation on the provided seeds. This may
    /// be useful where a HashBuilder is not desired, such as for testing purposes.
    ///
    /// # Example
    ///
    /// ```no_build
    /// use std::hash::Hasher;
    /// use ahash::AHasher;
    ///
    /// let mut hasher = AHasher::new_with_keys(1234, 5678);
    ///
    /// hasher.write_u32(1989);
    /// hasher.write_u8(11);
    /// hasher.write_u8(9);
    /// hasher.write(b"Huh?");
    ///
    /// println!("Hash is {:x}!", hasher.finish());
    /// ```
    #[inline]
    #[cfg(test)]
    pub(crate) fn new_with_keys(key1: u128, key2: u128) -> Self {
        let key1 = key1 ^ PI_U128X2[0];
        let key2 = key2 ^ PI_U128X2[1];
        Self {
            echo: key1,
            sum: add_by_64s(key1, key2),
            chain: key2,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_with_keys(key1: u128, key2: u128) -> Self {
        Self {
            echo: key1,
            sum: add_by_64s(key1, key2),
            chain: key2,
        }
    }

    #[inline]
    pub(crate) fn from_random_state<T>(rand_state: &RandomState<T>) -> Self {
        let key1 = [rand_state.k0, rand_state.k1].convert();
        let key2 = [rand_state.k2, rand_state.k3].convert();
        Self {
            echo: key1,
            sum: add_by_64s(key1, key2),
            chain: key2,
        }
    }

    /// Adds one value. Every state gets a round: the value goes into `chain`, the new `chain` into `echo`, the old
    /// `echo` into `sum`. A difference in a value is then in two states, one of which the input cannot reach, so
    /// the next value alone cannot cancel it.
    #[inline(always)]
    fn hash_in(&mut self, new_value: u128) {
        let (echo, sum, chain) = (self.echo, self.sum, self.chain);
        // The value is usually ready last, so the rounds do not wait for it.
        self.chain = aesenc_late(chain, new_value);
        self.echo = aesenc_late(sum, self.chain);
        self.sum = aesenc(echo, sum);
    }

    /// [Self::hash_in] for the first value of a `write`, with `sum_with_length` keying the round of the new `sum`.
    #[inline(always)]
    fn hash_in_first(&mut self, new_value: u128, sum_with_length: u128) {
        let (echo, sum, chain) = (self.echo, self.sum, self.chain);
        self.chain = aesenc_late(chain, new_value);
        self.echo = aesenc_late(sum, self.chain);
        self.sum = aesenc_late(echo, sum_with_length);
    }

    /// [Self::hash_in_first] followed by [Self::hash_in].
    #[inline(always)]
    fn hash_in_first_2(&mut self, v1: u128, v2: u128, sum_with_length: u128) {
        let (echo, sum, chain) = (self.echo, self.sum, self.chain);
        let chain1 = aesenc_late(chain, v1);
        let echo1 = aesenc_late(sum, chain1);
        let sum1 = aesenc_late(echo, sum_with_length);
        self.chain = aesenc(chain1, v2);
        self.echo = aesenc_late(sum1, self.chain);
        self.sum = aesenc(echo1, sum1);
    }

    /// [Self::hash_in] twice, for values after the first of a `write`. Here the rounds wait on the state, not the
    /// values, so the keys need not be applied late.
    #[inline(always)]
    fn hash_in_2(&mut self, v1: u128, v2: u128) {
        let (echo, sum, chain) = (self.echo, self.sum, self.chain);
        let chain1 = aesenc(chain, v1);
        let echo1 = aesenc(sum, chain1);
        let sum1 = aesenc(echo, sum);
        self.chain = aesenc(chain1, v2);
        self.echo = aesenc(sum1, self.chain);
        self.sum = aesenc(echo1, sum1);
    }

    /// Adds more than 128 bytes.
    ///
    /// Eight lanes, held as four pairs. Each 32 bytes go into one pair, and the 32 starting one byte later into the
    /// next, so every byte reaches two lanes at different positions and no part of the input can cancel the next.
    /// (Inlined like the rest of `write`: a call would pass the state through memory.)
    #[inline(always)]
    fn hash_in_long(&mut self, data: &[u8], sum_with_length: u128) {
        debug_assert!(data.len() > 128);
        let (echo, sum, chain) = (self.echo, self.sum, self.chain);
        // Each pair has its own secrets or operation, so no two lanes are related even on the same data.
        // `first_pairs[1]` carries the length.
        let first_pairs = [chain, aesenc_late(echo, sum_with_length)];
        let last_pairs = [echo, sum];
        // The last 128 bytes are read first, so the loop needs no special case for the end.
        let tail = &data[data.len() - 128..];
        let last = tail.read_last_u128x2();
        // The second use of the last 32 bytes wraps around to the first byte, which would otherwise be used once.
        let after_last = [
            shift_in_byte(last[0], last[1]),
            shift_in_byte(last[1], data.read_u128().0),
        ];
        let mut lanes: [[u128; 2]; 4] = [
            aesenc_x2(first_pairs, tail.read_u128x2().0),
            aesdec_x2(first_pairs, tail[1..].read_u128x2().0),
            aesenc_x2(last_pairs, tail[33..].read_u128x2().0),
            aesdec_x2(last_pairs, tail[65..].read_u128x2().0),
        ];
        lanes[1] = aesdec_x2(lanes[1], tail[32..].read_u128x2().0);
        lanes[2] = aesdec_x2(lanes[2], tail[64..].read_u128x2().0);
        lanes[3] = aesdec_x2(lanes[3], last);
        lanes[0] = aesdec_x2(lanes[0], after_last);
        // The rest, 128 bytes at a time. Each turn reads 129 bytes, always there while any are unread, so the last
        // turn rereads part of the tail.
        let mut data = data;
        while data.len() > 128 {
            hash_in_32_bytes(&mut lanes, 0, data);
            hash_in_32_bytes(&mut lanes, 1, &data[32..]);
            hash_in_32_bytes(&mut lanes, 2, &data[64..]);
            hash_in_32_bytes(&mut lanes, 3, &data[96..]);
            data = &data[128..];
        }
        // A lane's last input has had no round yet, so the last two pairs get one, then each lane is combined with one
        // of the first two pairs, which never received the same bytes.
        let zero = [0, 0];
        let [t0, t1] = aesenc_x2(aesenc_x2(lanes[2], zero), lanes[0]);
        let [t2, t3] = aesenc_x2(aesenc_x2(lanes[3], zero), lanes[1]);
        // Four values become three, each keying the round of the one before, so no difference stays in one.
        self.echo = aesenc(t1, t2);
        self.sum = aesenc(t0, t1);
        self.chain = aesenc(t2, t3);
    }

    /// For [AHasherFixed], which gets exactly one value: it goes into `sum`, which holds both keys, and its rounds
    /// are in [Self::fixed_finish]. (Elsewhere values are added after a round, so a run of them costs one
    /// operation each. With one value, the round can come after it, saving the rounds on the keys.)
    #[inline(always)]
    #[cfg(specialize)]
    fn hash_in_fixed(&mut self, value: u128) {
        self.sum = xor(self.sum, value);
    }

    #[inline]
    #[cfg(specialize)]
    fn fixed_finish(&self) -> u64 {
        // Both keys are in the first round's input, so each key bit gets as many rounds as the value.
        let c = aesenc(self.sum, self.echo);
        let a = aesenc(aesenc(c, self.chain), PI_U128X2[0]);
        cfg_if::cfg_if! {
            if #[cfg(any(
                all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"),
                target_arch = "aarch64"
            ))] {
                // Two bytes from each column, so each 32 bits of output depend on all 16 S-boxes of the last round,
                // which cannot be undone.
                spread_low64(a)
            } else {
                // Without a byte shuffle, a second stack does the same, as in `finish`.
                let b = aesdec(aesdec(c, PI_U128X2[0]), PI_U128X2[1]);
                let result: [u64; 2] = add_by_64s(a, b).convert();
                result[0]
            }
        }
    }
}

/// The first 32 bytes of `data` go into `lanes[pair]`, and the 32 bytes which start one byte later into the
/// pair after it.
#[inline(always)]
fn hash_in_32_bytes(lanes: &mut [[u128; 2]; 4], pair: usize, data: &[u8]) {
    lanes[pair] = aesdec_x2(lanes[pair], data.read_u128x2().0);
    lanes[(pair + 1) % 4] = aesdec_x2(lanes[(pair + 1) % 4], data[1..].read_u128x2().0);
}

/// Provides [Hasher] methods to hash all of the primitive types.
///
/// [Hasher]: core::hash::Hasher
impl Hasher for AHasher {
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.hash_in(i);
    }

    #[inline]
    #[cfg(any(
        target_pointer_width = "64",
        target_pointer_width = "32",
        target_pointer_width = "16"
    ))]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    #[cfg(target_pointer_width = "128")]
    fn write_usize(&mut self, i: usize) {
        self.write_u128(i as u128);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.write_u128(i as u128);
    }

    // (Always inlined: a call would pass the state through memory, which costs more than the hashing.)
    #[inline(always)]
    #[allow(clippy::collapsible_if)]
    fn write(&mut self, input: &[u8]) {
        let data = input;
        let length = data.len();
        // The length goes only into the key of the next `sum`, the state never holding a value as supplied. (A slice
        // hashes as its length, then its contents, so elsewhere the length could cancel a copy of itself.) The product
        // makes two lengths differ in all eight bytes, so cancelling takes eight S-boxes, and no two lengths collide.
        let mut sum_with_length = self.sum;
        add_in_length(&mut sum_with_length, (length as u64).wrapping_mul(MULTIPLE));

        // A binary search on the length keeps the comparisons few.
        if data.len() <= 8 {
            let value = read_small(data);
            self.hash_in_first(value.convert(), sum_with_length);
        } else {
            if data.len() > 32 {
                if data.len() > 64 {
                    if data.len() > 128 {
                        self.hash_in_long(data, sum_with_length);
                    } else {
                        //len 65-128
                        let (head, _) = data.read_u128x4();
                        let tail = data.read_last_u128x4();
                        self.hash_in_first_2(head[0], head[1], sum_with_length);
                        self.hash_in_2(head[2], head[3]);
                        self.hash_in_2(tail[0], tail[1]);
                        self.hash_in_2(tail[2], tail[3]);
                    }
                } else {
                    //len 33-64
                    let (head, _) = data.read_u128x2();
                    let tail = data.read_last_u128x2();
                    self.hash_in_first_2(head[0], head[1], sum_with_length);
                    self.hash_in_2(tail[0], tail[1]);
                }
            } else {
                if data.len() > 16 {
                    //len 17-32
                    self.hash_in_first_2(data.read_u128().0, data.read_last_u128(), sum_with_length);
                } else {
                    //len 9-16
                    let value: [u64; 2] = [data.read_u64().0, data.read_last_u64()];
                    self.hash_in_first(value.convert(), sum_with_length);
                }
            }
        }
    }
    #[inline]
    fn finish(&self) -> u64 {
        // Two stacks of three rounds from `chain`, so each 32 bits of output depend on eight last-round S-boxes.
        // (With one, the output difference for a fixed input difference is measurably non-uniform.) One decrypts, so
        // they share no S-box and differ as functions; otherwise `v ^ k` would collide with `v`. `sum`, with the
        // length, enters after `a`'s first round; `echo`'s older content, `chain ^ echo`, after `b`'s, two rounds
        // before the output (one round before, a difference there could cancel through only ten S-boxes).
        let a = aesenc(self.chain, self.sum);
        let b = aesdec(self.chain, PI_U128X2[0]);
        let a = aesenc(aesenc(a, PI_U128X2[1]), 0);
        let b = aesdec(aesdec(b, xor(self.chain, self.echo)), 0);
        let result: [u64; 2] = add_by_64s(a, b).convert();
        result[0]
    }
}

#[cfg(specialize)]
pub(crate) struct AHasherU64 {
    pub(crate) buffer: u64,
    pub(crate) pad: u64,
}

/// A specialized hasher for only primitives under 64 bits.
#[cfg(specialize)]
impl Hasher for AHasherU64 {
    #[inline]
    fn finish(&self) -> u64 {
        folded_multiply(self.buffer, self.pad)
    }

    #[inline]
    fn write(&mut self, _bytes: &[u8]) {
        unreachable!("Specialized hasher was called with a different type of object")
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.buffer = folded_multiply(i ^ self.buffer, MULTIPLE);
    }

    #[inline]
    fn write_u128(&mut self, _i: u128) {
        unreachable!("Specialized hasher was called with a different type of object")
    }

    #[inline]
    fn write_usize(&mut self, _i: usize) {
        unreachable!("Specialized hasher was called with a different type of object")
    }
}

#[cfg(specialize)]
pub(crate) struct AHasherFixed(pub AHasher);

/// A specialized hasher for primitives which are hashed as one value: `u128`, `i128`, `usize` and `isize`.
#[cfg(specialize)]
impl Hasher for AHasherFixed {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.fixed_finish()
    }

    #[inline]
    fn write(&mut self, _bytes: &[u8]) {
        unreachable!("Specialized hasher was called with a different type of object")
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0.hash_in_fixed(i as u128);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.0.hash_in_fixed(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0.hash_in_fixed(i as u128);
    }
}

#[cfg(specialize)]
pub(crate) struct AHasherStr(pub AHasher);

/// A specialized hasher for strings
/// Note that the other types don't panic because the hash impl for String tacks on an unneeded call. (As does vec)
#[cfg(specialize)]
impl Hasher for AHasherStr {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }

    #[inline]
    fn write_u8(&mut self, _i: u8) {}

    #[inline]
    fn write_u16(&mut self, _i: u16) {}

    #[inline]
    fn write_u32(&mut self, _i: u32) {}

    #[inline]
    fn write_u64(&mut self, _i: u64) {}

    #[inline]
    fn write_u128(&mut self, _i: u128) {}

    #[inline]
    fn write_usize(&mut self, _i: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::Convert;
    use crate::operations::aesenc;
    use crate::RandomState;
    use std::hash::{BuildHasher, Hasher};
    #[test]
    fn test_sanity() {
        let mut hasher = RandomState::<()>::with_seeds(1, 2, 3, 4).build_hasher();
        hasher.write_u64(0);
        let h1 = hasher.finish();
        hasher.write(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let h2 = hasher.finish();
        assert_ne!(h1, h2);
    }

    #[cfg(feature = "compile-time-rng")]
    #[test]
    fn test_builder() {
        use std::collections::HashMap;
        use std::hash::BuildHasherDefault;

        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }

    #[cfg(feature = "compile-time-rng")]
    #[test]
    fn test_default() {
        let hasher_a = AHasher::default();
        let a_echo: [u64; 2] = hasher_a.echo.convert();
        let a_sum: [u64; 2] = hasher_a.sum.convert();
        assert_ne!(0, a_echo[0]);
        assert_ne!(0, a_echo[1]);
        assert_ne!(0, a_sum[0]);
        assert_ne!(0, a_sum[1]);
        assert_ne!(a_echo[0], a_echo[1]);
        assert_ne!(a_sum[0], a_sum[1]);
        assert_ne!(a_echo[0], a_sum[0]);
        assert_ne!(a_echo[1], a_sum[1]);
        let hasher_b = AHasher::default();
        let b_echo: [u64; 2] = hasher_b.echo.convert();
        let b_sum: [u64; 2] = hasher_b.sum.convert();
        assert_eq!(a_echo[0], b_echo[0]);
        assert_eq!(a_echo[1], b_echo[1]);
        assert_eq!(a_sum[0], b_sum[0]);
        assert_eq!(a_sum[1], b_sum[1]);
    }

    #[test]
    fn test_hash() {
        let mut result: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value: [u64; 2] = [1 << 32, 0xFEDCBA9876543210];
        result = aesenc(value.convert(), result.convert()).convert();
        result = aesenc(result.convert(), result.convert()).convert();
        let mut result2: [u64; 2] = [0x6c62272e07bb0142, 0x62b821756295c58d];
        let value2: [u64; 2] = [1, 0xFEDCBA9876543210];
        result2 = aesenc(value2.convert(), result2.convert()).convert();
        result2 = aesenc(result2.convert(), result.convert()).convert();
        let result: [u8; 16] = result.convert();
        let result2: [u8; 16] = result2.convert();
        assert_ne!(hex::encode(result), hex::encode(result2));
    }
}
