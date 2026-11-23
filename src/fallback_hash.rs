use crate::convert::*;
use crate::operations::folded_multiply;
use crate::operations::multiply_halves;
use crate::operations::read_small;
use crate::operations::MULTIPLE;
use crate::random_state::PI_U128X2;
use crate::RandomState;
use core::hash::Hasher;

/// How far `large_update` rotates the buffer.
///
/// This also sets how likely the most likely known collision is: About one key in `2^(64 - ROT)`. So smaller is
/// better, until the factors of `2^(64 + ROT) - 1` and `2^(64 + ROT) + 1` come into play: When one operand is a
/// multiple of one factor, changing the other by a multiple of the rest can go unnoticed. For 15 these are
/// `2687 * 202029703 * 1113491139767` and three times a prime, which leaves nothing usable.
/// (This is for the real product. The substitute used where there is none also does best with 15 in the models.
/// See the tests of `large_update` below.)
const ROT: u32 = 15;

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
    buffer: u64,
    pad: u64,
    extra_keys: [u64; 2],
}

impl AHasher {
    /// Creates a new hasher keyed to the provided key.
    #[inline]
    #[allow(dead_code)] // Is not called if non-fallback hash is used.
    pub(crate) fn new_with_keys(key1: u128, key2: u128) -> AHasher {
        let key1: [u64; 2] = (key1 ^ PI_U128X2[0]).convert();
        let key2: [u64; 2] = (key2 ^ PI_U128X2[1]).convert();
        AHasher {
            buffer: key1[0],
            pad: key1[1],
            extra_keys: key2,
        }
    }

    #[allow(unused)] // False positive
    pub(crate) fn test_with_keys(key1: u128, key2: u128) -> Self {
        let key1: [u64; 2] = key1.convert();
        let key2: [u64; 2] = key2.convert();
        Self {
            buffer: key1[0],
            pad: key1[1],
            extra_keys: key2,
        }
    }

    #[inline]
    #[allow(dead_code)] // Is not called if non-fallback hash is used.
    pub(crate) fn from_random_state(rand_state: &RandomState) -> AHasher {
        AHasher {
            buffer: rand_state.k1,
            pad: rand_state.k0,
            extra_keys: [rand_state.k2, rand_state.k3],
        }
    }

    /// This update function has the goal of updating the buffer with a single multiply
    /// FxHash does this but is vulnerable to attack. To avoid this input needs to be masked to with an
    /// unpredictable value. Other hashes such as murmurhash have taken this approach but were found vulnerable
    /// to attack. The attack was based on the idea of reversing the pre-mixing (Which is necessarily
    /// reversible otherwise bits would be lost) then placing a difference in the highest bit before the
    /// multiply used to mix the data. Because a multiply can never affect the bits to the right of it, a
    /// subsequent update that also differed in this bit could result in a predictable collision.
    ///
    /// This version avoids this vulnerability while still only using a single multiply. It takes advantage
    /// of the fact that when a 64 bit multiply is performed the upper 64 bits are usually computed and thrown
    /// away. Instead it creates two 128 bit values where the upper 64 bits are zeros and multiplies them.
    /// (The compiler is smart enough to turn this into a 64 bit multiplication in the assembly)
    /// Then the upper bits are xored with the lower bits to produce a single 64 bit result.
    ///
    /// To understand why this is a good scrambling function it helps to understand multiply-with-carry PRNGs:
    /// https://en.wikipedia.org/wiki/Multiply-with-carry_pseudorandom_number_generator
    /// If the multiple is chosen well, this creates a long period, decent quality PRNG.
    /// Notice that this function is equivalent to this except the `buffer`/`state` is being xored with each
    /// new block of data. In the event that data is all zeros, it is exactly equivalent to an MWC PRNG.
    ///
    /// This is impervious to attack because every bit buffer at the end is dependent on every bit in
    /// `new_data ^ buffer`. For example suppose two inputs differed in only the 5th bit. Then when the
    /// multiplication is performed the `result` will differ in bits 5-69. More specifically it will differ by
    /// 2^5 * MULTIPLE. However in the next step bits 65-128 are turned into a separate 64 bit value. So the
    /// differing bits will be in the lower 6 bits of this value. The two intermediate values that differ in
    /// bits 5-63 and in bits 0-5 respectively get added together. Producing an output that differs in every
    /// bit. The addition carries in the multiplication and at the end additionally mean that even if an
    /// attacker somehow knew part of (but not all) the contents of the buffer beforehand,
    /// they would not be able to predict any of the bits in the buffer at the end.
    #[inline(always)]
    fn update(&mut self, new_data: u64) {
        self.buffer = folded_multiply(new_data ^ self.buffer, MULTIPLE);
    }

    /// Similar to the above this function performs an update using a multiply.
    /// However it takes in 128 bits of data instead of 64. Both halves must be masked.
    ///
    /// Unlike in `update` both operands of the multiply are controlled by the input, so the two halves of the
    /// product must not simply be xored together (See [multiply_halves]). Instead the low half is xored into the
    /// buffer before it is rotated and the high half is added afterwards. A change to the input which moves one
    /// half up and the other down then lands in two different positions, via two different operations, and does
    /// not offset itself. Because xor and add do not commute and the rotation moves the bits, the buffer is also
    /// updated in a way which prevents (a,b) from hashing the same as (b,a).
    ///
    /// `pad` is added along with the high half, off the path from one block to the next. It makes no difference
    /// to whether two blocks collide, but without it the key in `pad` would only reach the state when finishing,
    /// through a single multiply. (Where there is no 128 bit product, that leaves bits it cannot change.)
    ///
    /// The price of the rotation: When one operand happens to be small, a difference in a single bit of the
    /// other changes a short run of bits which lies partly in each half, and these can line up and cancel.
    /// This is the most likely collision that is known for a single block, at about one key in `2^(64 - ROT)`.
    #[inline(always)]
    fn large_update(&mut self, new_data: u128) {
        let block: [u64; 2] = new_data.convert();
        let [low, high] = multiply_halves(block[0] ^ self.extra_keys[0], block[1] ^ self.extra_keys[1]);
        let high = high.wrapping_add(self.pad);
        self.buffer = (self.buffer ^ low).rotate_left(ROT).wrapping_add(high);
    }

    #[inline]
    #[cfg(specialize)]
    fn short_finish(&self) -> u64 {
        folded_multiply(self.buffer, self.pad)
    }
}

/// Provides [Hasher] methods to hash all of the primitive types.
///
/// [Hasher]: core::hash::Hasher
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
        self.update(i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.large_update(i);
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
    #[allow(clippy::collapsible_if)]
    fn write(&mut self, input: &[u8]) {
        let mut data = input;
        let length = data.len() as u64;
        //Needs to be an add rather than an xor because otherwise it could be canceled with carefully formed input.
        self.buffer = self.buffer.wrapping_add(length).wrapping_mul(MULTIPLE);
        //A 'binary search' on sizes reduces the number of comparisons.
        if data.len() > 8 {
            if data.len() > 16 {
                let tail = data.read_last_u128();
                self.large_update(tail);
                while data.len() > 16 {
                    let (block, rest) = data.read_u128();
                    self.large_update(block);
                    data = rest;
                }
            } else {
                self.large_update([data.read_u64().0, data.read_last_u64()].convert());
            }
        } else {
            let value = read_small(data);
            self.large_update(value.convert());
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        let rot = (self.buffer & 63) as u32;
        folded_multiply(self.buffer, self.pad).rotate_left(rot)
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
        //self.buffer
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

/// A specialized hasher for fixed size primitives larger than 64 bits.
#[cfg(specialize)]
impl Hasher for AHasherFixed {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.short_finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
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
        self.0.write_u64(i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.0.write_u128(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0.write_usize(i);
    }
}

#[cfg(specialize)]
pub(crate) struct AHasherStr(pub AHasher);

/// A specialized hasher for a single string
/// Note that the other types don't panic because the hash impl for String tacks on an unneeded call. (As does vec)
#[cfg(specialize)]
impl Hasher for AHasherStr {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() > 8 {
            self.0.write(bytes)
        } else {
            let value = read_small(bytes);
            // Both operands depend on the input here too, but only in their low 32 bits. Xoring the halves of
            // the product is only a problem when all of the bits of an operand can be complemented.
            // (See `test_short_string_differences_do_not_scale`.)
            self.0.buffer = folded_multiply(value[0] ^ self.0.buffer, value[1] ^ self.0.extra_keys[1]);
            self.0.pad = self.0.pad.wrapping_add(bytes.len() as u64);
        }
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
    use crate::fallback_hash::*;

    #[test]
    fn test_hash() {
        let mut hasher = AHasher::new_with_keys(0, 0);
        let value: u64 = 1 << 32;
        hasher.update(value);
        let result = hasher.buffer;
        let mut hasher = AHasher::new_with_keys(0, 0);
        let value2: u64 = 1;
        hasher.update(value2);
        let result2 = hasher.buffer;
        let result: [u8; 8] = result.convert();
        let result2: [u8; 8] = result2.convert();
        assert_ne!(hex::encode(result), hex::encode(result2));
    }

    // The 64 bit function is too large to measure how often two different blocks collide. But the weaknesses
    // of `large_update` come from the arithmetic, and exist at every word size. So the tests below use a
    // model of it with small words, where every key can be tried. (All of the rotations scale with the
    // word size.) Rates are given as a multiple of the `2^-width` that an ideal function would have.

    type Halves = fn(u64, u64, u32) -> [u64; 2];
    type Combine = fn(u64, [u64; 2], u32) -> u64;

    fn mask(width: u32) -> u64 {
        u64::MAX >> (64 - width)
    }

    /// `ROT` scaled to the word size.
    fn scaled_rot(width: u32) -> u32 {
        (ROT * width + 32) / 64
    }

    fn rotate(value: u64, width: u32) -> u64 {
        let rot = scaled_rot(width);
        ((value << rot) | (value >> (width - rot))) & mask(width)
    }

    /// The model of `multiply_halves` where there is a 128 bit product.
    fn product_halves(x: u64, y: u64, width: u32) -> [u64; 2] {
        let product = (x as u128) * (y as u128);
        [product as u64 & mask(width), (product >> width) as u64 & mask(width)]
    }

    /// `swap_bytes` for a word of 8 bytes (at 64 bits) or of four smaller "bytes".
    fn swap(value: u64, width: u32) -> u64 {
        let bytes = if width == 64 { 8 } else { 4 };
        let bits = width / bytes;
        (0..bytes).fold(0, |result, i| {
            result | ((value >> (i * bits)) & mask(bits)) << ((bytes - 1 - i) * bits)
        })
    }

    /// The model of `multiply_halves` where there is no 128 bit product.
    fn substitute_halves(x: u64, y: u64, width: u32) -> [u64; 2] {
        let b1 = x.wrapping_mul(swap(y, width)) & mask(width);
        let b2 = swap(x, width).wrapping_mul(!y & mask(width)) & mask(width);
        [b1, swap(b2, width)]
    }

    /// The model of `multiply_halves` on this platform.
    #[cfg(folded_multiply)]
    const HALVES: Halves = product_halves;
    #[cfg(not(folded_multiply))]
    const HALVES: Halves = substitute_halves;

    /// The model of `large_update`.
    fn combine(buffer: u64, [low, high]: [u64; 2], width: u32) -> u64 {
        rotate(buffer ^ low, width).wrapping_add(high) & mask(width)
    }

    /// The model of `AHasherStr` for short strings, which xors the halves together.
    fn fold(_buffer: u64, [low, high]: [u64; 2], _width: u32) -> u64 {
        low ^ high
    }

    #[test]
    fn test_large_update_matches_model() {
        for (data, key1, key2) in [
            (0_u128, 0_u128, 0_u128),
            (1, 2, 3),
            (u128::MAX, 1 << 80, 7),
            (0x0123_4567_89ab_cdef_0011_2233_4455_6677, 99, 12345),
            (0xfedc_ba98_7654_3210_8899_aabb_ccdd_eeff, u128::MAX / 3, u128::MAX / 5),
        ] {
            let mut hasher = AHasher::test_with_keys(key1, key2);
            let block: [u64; 2] = data.convert();
            let (x, y) = (block[0] ^ hasher.extra_keys[0], block[1] ^ hasher.extra_keys[1]);
            // (`pad` is a constant which is added to every state, so it cancels when two blocks are compared, and
            // the models leave it out.)
            let expected = combine(hasher.buffer, HALVES(x, y, 64), 64).wrapping_add(hasher.pad);
            hasher.large_update(data);
            assert_eq!(expected, hasher.buffer);
        }
    }

    #[test]
    fn test_model_matches_multiply_halves() {
        for (x, y) in [
            (0_u64, 0_u64),
            (3, 5),
            (u64::MAX, u64::MAX),
            (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
        ] {
            assert_eq!(multiply_halves(x, y), HALVES(x, y, 64));
        }
    }

    /// For every possible difference between two blocks: How often they leave the buffer in the same state.
    /// The difference `(da, db)` is at index `da << width | db`.
    /// (The keys are xored with the input before it is used. So trying every pair of operands is trying every key.)
    fn difference_profile(halves: Halves, combine: Combine, width: u32, buffers: u64) -> Vec<f64> {
        let size = 1_usize << width;
        let mut counts = vec![0_u32; size * size];
        let mut states: Vec<Vec<u32>> = vec![Vec::new(); size];
        for i in 0..buffers {
            let buffer = (i + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - width);
            states.iter_mut().for_each(Vec::clear);
            for x in 0..size as u64 {
                for y in 0..size as u64 {
                    let state = combine(buffer, halves(x, y, width), width);
                    states[state as usize].push((x << width | y) as u32);
                }
            }
            // Any two operand pairs which lead to the same state are a collision for the difference between them.
            for state in states.iter() {
                for (i, a) in state.iter().enumerate() {
                    for b in &state[i + 1..] {
                        counts[(a ^ b) as usize] += 1;
                    }
                }
            }
        }
        let ideal = (size as u64 * buffers) as f64 / 2.0;
        counts.into_iter().map(|count| count as f64 / ideal).collect()
    }

    /// The same for a single difference, which is feasible for larger words.
    fn collision_rate(halves: Halves, combine: Combine, width: u32, da: u64, db: u64) -> f64 {
        let size = 1_u64 << width;
        let mut collisions = 0_u64;
        for x in 0..size {
            for y in 0..size {
                let buffer =
                    (x.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ y.wrapping_mul(0x85eb_ca6b_1234_5677)) >> (64 - width);
                let a = combine(buffer, halves(x, y, width), width);
                let b = combine(buffer, halves(x ^ da, y ^ db, width), width);
                collisions += (a == b) as u64;
            }
        }
        collisions as f64 / size as f64
    }

    fn worst(profile: &[f64], width: u32, include: impl Fn(u64, u64) -> bool) -> (f64, u64, u64) {
        let mut worst = (0.0, 0, 0);
        for (index, &rate) in profile.iter().enumerate().skip(1) {
            let (da, db) = (index as u64 >> width, index as u64 & mask(width));
            if rate > worst.0 && include(da, db) {
                worst = (rate, da, db);
            }
        }
        worst
    }

    /// Differences in one bit: Of either operand, or the same bit of both.
    fn single_bits(width: u32) -> impl Iterator<Item = (u64, u64)> {
        (0..width).flat_map(|bit| [(1 << bit, 1 << bit), (1 << bit, 0), (0, 1 << bit)])
    }

    /// Checks every possible difference between two blocks, so that no pattern (like the complement in issue #292,
    /// which collided 2^38 times more often than ideal at 64 bits) can stand out. This is not an ideal function,
    /// and it is not expected to be: See the next test for what the worst of these are, and what they amount to.
    /// The model of the substitute is cruder than the one of the product, because the function works on bytes and
    /// a word here has only four of them, of two bits each. (The worst measured are 3.9 and 6.9 times ideal.)
    #[test]
    fn test_no_block_difference_collides_often() {
        let width = 8;
        for (halves, limit) in [(product_halves as Halves, 6.0), (substitute_halves, 9.0)] {
            let profile = difference_profile(halves, combine, width, 32);
            let (rate, da, db) = worst(&profile, width, |_, _| true);
            assert!(
                rate < limit,
                "A difference of {:x?} collides {} times more often than ideal",
                (da, db),
                rate
            );
        }
    }

    /// The price of not xoring the halves together: When one operand is small, changing one bit of the other
    /// changes a short run of bits in the product, which lies partly in each half. As the low half is rotated
    /// relative to the high half, these two parts can end up on top of each other and cancel out.
    ///
    /// For the product this depends on the rotation and not on the word size: It is about `2^(rot - 1)` times the
    /// ideal rate for a bit of one operand, and up to `2^rot` times for the same bit of both. For the real
    /// function that is `2^15 * 2^-64`, or one key in 2^49. See `test_single_bit_differences_at_full_width` for
    /// the same measurement on the real function. The substitute is somewhat worse in the model: 1.3 and 2.3
    /// times `2^rot` at 8 and 12 bits, against 0.9 and 1.0 for the product.
    #[test]
    fn test_single_bit_differences_are_limited_by_rotation() {
        for (halves, factor) in [(product_halves as Halves, 1.25), (substitute_halves, 3.0)] {
            for width in [8, 12] {
                let limit = factor * (1 << scaled_rot(width)) as f64;
                for (da, db) in single_bits(width) {
                    let rate = collision_rate(halves, combine, width, da, db);
                    assert!(
                        rate < limit,
                        "At {} bits a difference of {:x?} collides {} times more often than ideal",
                        width,
                        (da, db),
                        rate
                    );
                }
            }
        }
    }

    /// `AHasherStr` xors the halves of a product of two operands which both depend on the input, for strings of
    /// up to 8 bytes. But there the input only reaches the low half of each operand. Check that no difference
    /// which is confined to the low halves stands out, or grows with the word size the way the complement did.
    #[test]
    fn test_short_string_differences_do_not_scale() {
        for halves in [product_halves as Halves, substitute_halves] {
            let width = 8;
            let half = mask(width / 2);
            let profile = difference_profile(halves, fold, width, 1);
            let (rate, da, db) = worst(&profile, width, |da, db| da <= half && db <= half);
            assert!(rate < 6.0, "{:x?} {}", (da, db), rate);
            let width = 12;
            let half = mask(width / 2);
            for (da, db) in [(half, half), (half, 0), (0, half)] {
                let rate = collision_rate(halves, fold, width, da, db);
                assert!(rate < 6.0, "{:x?} {}", (da, db), rate);
            }
        }
    }

    /// The chance that two blocks whose operands differ by `(da, db)` leave a random buffer in the same state,
    /// for these particular operands. This can be computed rather than counted, which makes the real word size
    /// reachable: With `u = rotl(buffer ^ low)` the states are `u + high` and `(u ^ d) + high'`, where
    /// `d = rotl(low ^ low')`. Each bit set in `d` moves `u` up or down by that bit, depending on whether
    /// it is set in `u`. So they are equal exactly when `2 * (u & d) - d == high' - high`.
    #[cfg(folded_multiply)]
    fn collision_chance(x: u64, y: u64, da: u64, db: u64) -> f64 {
        let [low, high] = multiply_halves(x, y);
        let [low2, high2] = multiply_halves(x ^ da, y ^ db);
        let d = (low ^ low2).rotate_left(ROT);
        if d == 0 {
            return (high == high2) as u64 as f64;
        }
        let sum = high2.wrapping_sub(high).wrapping_add(d);
        if sum & 1 != 0 {
            return 0.0;
        }
        // `u & d` is half of the sum. Its top bit could be either value.
        let candidates = [sum >> 1, sum >> 1 | 1 << 63];
        let count = candidates.iter().filter(|&bits| bits & !d == 0).count();
        count as f64 / 2_f64.powi(d.count_ones() as i32)
    }

    /// Measures how often a difference in one bit collides, at the real word size, as a multiple of 2^-64.
    /// Such collisions come from the keys where the other operand is a short value, shifted left by some amount.
    /// So rather than drawing it uniformly, every length and shift is drawn equally often and the result is
    /// weighted by how common such operands are.
    /// (Shapes for which it would take around 2^32 samples to see anything contribute nothing here. The whole
    /// of an ideal function is like that, so this only measures the excess.)
    #[cfg(folded_multiply)]
    fn single_bit_rate(da: u64, db: u64, samples: u64) -> f64 {
        let mut state = da ^ db.rotate_left(32);
        let mut next = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let z = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            let z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut total = 0.0;
        for _ in 0..samples {
            // An odd value of `length` bits, followed by `shift` zeros.
            let length = 1 + next() % 64;
            let shift = next() % (65 - length);
            let short = ((next() | 1 << 63) >> (64 - length) | 1) << shift;
            let (x, y) = if da != 0 { (next(), short) } else { (short, next()) };
            // This is one of 64 lengths and `65 - length` shifts, and there are `2^(length - 2)` such values.
            let weight = 64.0 * (65 - length) as f64 * 2_f64.powi(length as i32 - 2).max(1.0);
            total += collision_chance(x, y, da, db) * weight;
        }
        total / samples as f64
    }

    /// The small models say a difference in a single bit collides about `2^(ROT - 1)` times more often than
    /// ideal (up to `2^ROT` for the same bit of both operands). This checks that the real function is no worse.
    /// (With 2^28 samples, every fourth bit from 16 to 48 of either operand comes out between 2^13.8 and 2^14.2.
    /// The same bit of both operands reaches 2^15.0.)
    #[cfg(folded_multiply)]
    #[test]
    fn test_single_bit_differences_at_full_width() {
        let limit = 3.0 * 2_f64.powi(ROT as i32 - 1);
        for (da, db) in [(1 << 36, 0), (0, 1 << 36), (1 << 36, 1 << 36)] {
            let rate = single_bit_rate(da, db, 1 << 24);
            assert!(
                rate < limit,
                "A difference of {:x?} collides 2^{:.1} times more often than ideal",
                (da, db),
                rate.log2()
            );
        }
    }
}
