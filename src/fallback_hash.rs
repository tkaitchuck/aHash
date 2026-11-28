use crate::convert::*;
use crate::operations::add_by_64s;
use crate::operations::folded_multiply;
use crate::operations::multiply_halves;
use crate::operations::read_small;
use crate::operations::xor;
use crate::operations::MULTIPLE;
use crate::random_state::PI_U128X2;
use crate::RandomState;
use core::hash::Hasher;

/// How far `combine` rotates the word of the buffer which the high half was added to.
///
/// It is there so that a later block cannot undo what an earlier one did to a word with the same change to its
/// input. (Without it, long inputs which are mostly zeros collide.) Were the keys the same for every block, 25
/// would make blocks with a word in common least likely to collide: About one key in `2^42`. It is odd, so a word
/// is back in the same position only after 128 blocks.
const ROT: u32 = 25;

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
    /// The halves of each block's product go into one word each, and the words change places.
    buffer: [u64; 2],
    /// Xored with each block before it is multiplied. `increments` is added after every block.
    keys: [u64; 2],
    /// Always odd.
    increments: [u64; 2],
}

/// What is added to the keys after each block: The sum of where the buffer and the keys start, so that it is secret
/// too, and odd, so that each key differs from the one before.
///
/// It is one add, as a hasher is built for every value hashed. It is not an xor, because `new_with_keys` xors each
/// key with a constant: Given the same key twice, an xor of the two would leave only the constants.
#[inline(always)]
fn increments(buffer: [u64; 2], keys: [u64; 2]) -> [u64; 2] {
    let sum: [u64; 2] = add_by_64s(buffer.convert(), keys.convert()).convert();
    [sum[0] | 1, sum[1] | 1]
}

impl AHasher {
    /// Creates a new hasher keyed to the provided key.
    #[inline]
    #[cfg(test)]
    pub(crate) fn new_with_keys(key1: u128, key2: u128) -> AHasher {
        let key1: [u64; 2] = (key1 ^ PI_U128X2[0]).convert();
        let key2: [u64; 2] = (key2 ^ PI_U128X2[1]).convert();
        AHasher {
            buffer: key1,
            keys: key2,
            increments: increments(key1, key2),
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn test_with_keys(key1: u128, key2: u128) -> Self {
        let key1: [u64; 2] = key1.convert();
        let key2: [u64; 2] = key2.convert();
        Self {
            buffer: key1,
            keys: key2,
            increments: increments(key1, key2),
        }
    }

    #[inline]
    #[allow(dead_code)] // Is not called if non-fallback hash is used.
    pub(crate) fn from_random_state(rand_state: &RandomState) -> AHasher {
        let buffer = [rand_state.k0, rand_state.k1];
        let keys = [rand_state.k2, rand_state.k3];
        AHasher {
            buffer,
            keys,
            increments: increments(buffer, keys),
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
    /// away. Instead, it creates two 128 bit values where the upper 64 bits are zeros and multiplies them.
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
    /// 2^5 * MULTIPLE. However, in the next step bits 65-128 are turned into a separate 64 bit value. So the
    /// differing bits will be in the lower 6 bits of this value. The two intermediate values that differ in
    /// bits 5-63 and in bits 0-5 respectively get added together. Producing an output that differs in every
    /// bit. The addition carries in the multiplication and at the end additionally mean that even if an
    /// attacker somehow knew part of (but not all) the contents of the buffer beforehand,
    /// they would not be able to predict any of the bits in the buffer at the end.
    #[inline(always)]
    fn update(&mut self, new_data: u64) {
        self.buffer[0] = folded_multiply(new_data ^ self.buffer[0], MULTIPLE);
    }

    /// Similar to the above this function performs an update using a multiply.
    /// However it takes in 128 bits of data instead of 64, and xors each half with a key itself.
    ///
    /// Unlike in `update` both operands of the multiply are derived from the input, so the two halves of the product
    /// go into the two words of the buffer. (See `combine`.)
    ///
    /// The keys change after every block so the same delta cannot be applied repeatedly.
    #[inline(always)]
    fn hash_in(&mut self, new_value: u128) {
        // (A word at a time, so that nothing comes between the input and the multiply.)
        let block: [u64; 2] = new_value.convert();
        self.buffer = Self::combine(self.buffer, [block[0] ^ self.keys[0], block[1] ^ self.keys[1]]);
        self.keys = [
            self.keys[0].wrapping_add(self.increments[0]),
            self.keys[1].wrapping_add(self.increments[1]),
        ];
    }

    /// Performs a wide multiply and xors and adds the halves in to the buffer.
    /// The added side is rotated to introduce asymmetry and the halves are swapped.
    /// (Addition and xors don't commute.)
    #[inline(always)]
    fn combine([added, xored]: [u64; 2], [s, by]: [u64; 2]) -> [u64; 2] {
        let [low, high] = multiply_halves(s, by);
        [xored.wrapping_add(high), added.rotate_left(ROT) ^ low]
    }

    /// `hash_in` for two blocks. After it the words of the buffer are back where they started.
    #[inline(always)]
    fn hash_in_2(&mut self, first: u128, second: u128) {
        self.hash_in(first);
        self.hash_in(second);
    }

    /// Process data > 32 bytes.
    #[inline(always)]
    fn hash_in_long(&mut self, mut data: &[u8]) {
        debug_assert!(data.len() > 32);
        // (These products are needed first, so they take their keys the way `hash_in` does.)
        let [first, second] = data.read_last_u128x2();
        self.hash_in_2(first, second);
        let mut buffer = self.buffer;
        let mut keys: u128 = self.keys.convert();
        let increments: u128 = self.increments.convert();
        while data.len() > 32 {
            let (blocks, rest) = data.read_u128x2();
            for block in blocks {
                // (The keys stay in a vector register: One load, one xor and one add for a block. The operands
                // then have to be moved to be multiplied, but in a loop they are ready before the buffer is.)
                let operands: [u64; 2] = xor(block, keys).convert();
                keys = add_by_64s(keys, increments);
                buffer = Self::combine(buffer, operands);
            }
            data = rest;
        }
        self.buffer = buffer;
        self.keys = keys.convert();
    }

    /// Adds the length of a `write` to the buffer.
    #[inline(always)]
    fn add_length(&mut self, length: usize) {
        //Needs to be an add rather than an xor because otherwise it could be canceled with carefully formed input.
        self.buffer[0] = self.buffer[0].wrapping_add(length as u64).wrapping_mul(MULTIPLE);
    }

    #[inline]
    #[cfg(specialize)]
    fn short_finish(&self) -> u64 {
        folded_multiply(self.buffer[0], self.buffer[1])
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

    // (Up to 16 bytes inlined: a call would pass the state through memory. Longer input does make one, so that what
    // is inlined stays small enough for LLVM to also inline the callers of `write`, such as `write_str`.)
    #[inline(always)]
    fn write(&mut self, input: &[u8]) {
        if input.len() <= 16 {
            self.add_length(input.len());
            // (One block for both lengths, so that there is one copy of it to inline.)
            let value = if input.len() > 8 {
                [input.read_u64().0, input.read_last_u64()]
            } else {
                read_small(input)
            };
            self.hash_in(value.convert());
        } else {
            let (low, high) = write_over_16(self.buffer[0], self.buffer[1], &mut self.keys, &self.increments, input);
            self.buffer = [low, high];
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        let rot = (self.buffer[0] & 63) as u32;
        folded_multiply(self.buffer[0], self.buffer[1]).rotate_left(rot)
    }
}

/// [AHasher::write] for more than 16 bytes: Takes the buffer and returns it updated, and steps `keys`.
///
/// (The buffer goes both ways in registers: As a `[u64; 2]` it would go through memory. The keys and increments go
/// by reference: By value there would be more arguments than registers to pass them in.)
#[inline(never)]
fn write_over_16(low: u64, high: u64, keys: &mut [u64; 2], increments: &[u64; 2], data: &[u8]) -> (u64, u64) {
    debug_assert!(data.len() > 16);
    let mut hasher = AHasher {
        buffer: [low, high],
        keys: *keys,
        increments: *increments,
    };
    hasher.add_length(data.len());
    //A 'binary search' on sizes reduces the number of comparisons.
    if data.len() > 32 {
        if data.len() > 64 {
            hasher.hash_in_long(data);
        } else {
            //len 33-64, in the order `hash_in_long` would take it
            let [first, second] = data.read_last_u128x2();
            hasher.hash_in_2(first, second);
            let ([first, second], _) = data.read_u128x2();
            hasher.hash_in_2(first, second);
        }
    } else {
        //len 17-32
        hasher.hash_in_2(data.read_u128().0, data.read_last_u128());
    }
    *keys = hasher.keys;
    (hasher.buffer[0], hasher.buffer[1])
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
    fn write_u128(&mut self, i: u128) {
        let i: [u64; 2] = i.convert();
        self.buffer = folded_multiply(i[0] ^ self.buffer, MULTIPLE);
        self.pad = folded_multiply(i[1] ^ self.pad, MULTIPLE);
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
            self.0.buffer[0] = folded_multiply(value[0] ^ self.0.buffer[0], value[1] ^ self.0.keys[1]);
            self.0.buffer[1] = self.0.buffer[1].wrapping_add(bytes.len() as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, _i: u8) {}

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.0.write_u16(i)
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0.write_u32(i)
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0.write_u64(i)
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.0.write_u128(i)
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0.write_usize(i)
    }
}

#[cfg(test)]
mod tests {
    use crate::fallback_hash::*;

    #[test]
    fn test_hash() {
        let mut hasher = AHasher::new_with_keys(0, 0);
        let value: u64 = 1 << 32;
        hasher.update(value);
        let result = hasher.buffer[0];
        let mut hasher = AHasher::new_with_keys(0, 0);
        let value2: u64 = 1;
        hasher.update(value2);
        let result2 = hasher.buffer[0];
        let result: [u8; 8] = result.convert();
        let result2: [u8; 8] = result2.convert();
        assert_ne!(hex::encode(result), hex::encode(result2));
    }

    /// An even increment would leave the low bit of a key the same for every block, and zero the whole key.
    #[test]
    fn test_increments_are_odd() {
        for (key1, key2) in [
            (0_u128, 0_u128),
            (1, 1),
            (u128::MAX, 1),
            (1 << 64, 1 << 64),
            (3, 5 << 64),
        ] {
            let ([k0, k1], [k2, k3]): ([u64; 2], [u64; 2]) = (key1.convert(), key2.convert());
            for hasher in [
                AHasher::new_with_keys(key1, key2),
                AHasher::test_with_keys(key1, key2),
                AHasher::from_random_state(&RandomState { k0, k1, k2, k3 }),
            ] {
                assert_eq!([1, 1], [hasher.increments[0] & 1, hasher.increments[1] & 1]);
            }
        }
    }

    // The 64 bit function is too large to measure how often two different blocks collide. But the weaknesses
    // of `hash_in` come from the arithmetic, and exist at every word size. So the tests below use a
    // model of it with small words, where every key can be tried. (All of the rotations scale with the
    // word size.) Rates are given as a multiple of `2^-width`, which is the chance that any two inputs collide in
    // the one word `finish` returns.
    //
    // This is the bar even where the state compared is two words: A product of two words does not do better than
    // one word. If an operand is zero (one key in `2^width`) any difference in the other has no effect, and if the
    // operands are swapped the product is the same. So two words of state collide at about `2^-width` for some
    // differences however the halves are combined, which adds at most as much as the output's own rate.

    /// What two blocks are compared by: Equal results are a collision.
    type Outcome = fn([u64; 2], u32) -> u64;

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

    /// The model of `multiply_halves`.
    fn product_halves(x: u64, y: u64, width: u32) -> [u64; 2] {
        let product = (x as u128) * (y as u128);
        [product as u64 & mask(width), (product >> width) as u64 & mask(width)]
    }

    /// The model of `AHasher::combine`.
    fn combine([added, xored]: [u64; 2], [x, y]: [u64; 2], width: u32) -> [u64; 2] {
        let [low, high] = product_halves(x, y, width);
        [xored.wrapping_add(high) & mask(width), rotate(added, width) ^ low]
    }

    /// The model of `AHasherStr` for short strings, which xors the halves together.
    fn fold([low, high]: [u64; 2], _width: u32) -> u64 {
        low ^ high
    }

    #[test]
    fn test_hash_in_matches_model() {
        for (data, key1, key2) in [
            (0_u128, 0_u128, 0_u128),
            (1, 2, 3),
            (u128::MAX, 1 << 80, 7),
            (0x0123_4567_89ab_cdef_0011_2233_4455_6677, 99, 12345),
            (0xfedc_ba98_7654_3210_8899_aabb_ccdd_eeff, u128::MAX / 3, u128::MAX / 5),
        ] {
            let mut hasher = AHasher::test_with_keys(key1, key2);
            // Two blocks, so that the second one meets keys which have moved on.
            for _ in 0..2 {
                let block: [u64; 2] = data.convert();
                let (keys, increments) = (hasher.keys, hasher.increments);
                let expected = combine(hasher.buffer, [block[0] ^ keys[0], block[1] ^ keys[1]], 64);
                hasher.hash_in(data);
                assert_eq!(expected, hasher.buffer);
                assert_eq!(
                    [keys[0].wrapping_add(increments[0]), keys[1].wrapping_add(increments[1])],
                    hasher.keys
                );
            }
        }
    }

    /// `write` adds the length and then does `hash_in` for each block of the input: Up to 16 bytes are one
    /// block, and up to 32 the first 16 and the last 16. Longer inputs are the last 32 bytes, and then each 32 from
    /// the start while more than 32 remain. (Each number of blocks has code of its own.)
    #[test]
    fn test_write_is_hash_in_for_each_block() {
        let data: Vec<u8> = (0..150_u32).map(|i| (i * 37 + 11) as u8).collect();
        for length in 0..=data.len() {
            let data = &data[..length];
            let mut written = AHasher::test_with_keys(length as u128, 99);
            let mut expected = written.clone();
            written.write(data);
            expected.buffer[0] = expected.buffer[0].wrapping_add(length as u64).wrapping_mul(MULTIPLE);
            let mut blocks: Vec<u128> = Vec::new();
            if length <= 8 {
                blocks.push(read_small(data).convert());
            } else if length <= 16 {
                blocks.push([data.read_u64().0, data.read_last_u64()].convert());
            } else if length <= 32 {
                blocks.extend([data.read_u128().0, data.read_last_u128()]);
            } else {
                blocks.extend(data.read_last_u128x2());
                let mut rest = data;
                while rest.len() > 32 {
                    let (pair, after) = rest.read_u128x2();
                    blocks.extend(pair);
                    rest = after;
                }
            }
            for block in blocks {
                expected.hash_in(block);
            }
            assert_eq!(
                (expected.buffer, expected.keys),
                (written.buffer, written.keys),
                "{}",
                length
            );
        }
    }

    /// Where there is no 128 bit multiply the product is put together from four smaller ones. It has to be the
    /// same product, as the models assume it is.
    #[test]
    fn test_multiply_halves_by_32s_is_the_product() {
        use crate::operations::multiply_halves_by_32s;
        let mut seed = 1;
        let mut operands = vec![
            (0_u64, 0_u64),
            (3, 5),
            (u64::MAX, u64::MAX),
            (u64::MAX, 1 << 32),
            (0xffff_ffff, 0xffff_ffff),
            (0xffff_ffff_0000_0001, 0x0000_0001_ffff_ffff),
        ];
        operands.extend((0..10_000).map(|_| (random(&mut seed), random(&mut seed))));
        for (x, y) in operands {
            assert_eq!(
                multiply_halves_by_32s(x, y),
                product_halves(x, y, 64),
                "{:x} {:x}",
                x,
                y
            );
        }
    }

    /// For every possible difference between two blocks: How often they have the same `outcome`, which may have
    /// up to twice the width (but is held to the same rate, see above). The difference `(da, db)` is at index
    /// `da << width | db`.
    /// (The keys are xored with the input before it is used. So trying every pair of operands is trying every key.)
    fn difference_profile(outcome: Outcome, width: u32) -> Vec<f64> {
        let size = 1_usize << width;
        let mut counts = vec![0_u32; size * size];
        let mut states: Vec<Vec<u32>> = vec![Vec::new(); size * size];
        for x in 0..size as u64 {
            for y in 0..size as u64 {
                let state = outcome(product_halves(x, y, width), width);
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
        let ideal = size as f64 / 2.0;
        counts.into_iter().map(|count| count as f64 / ideal).collect()
    }

    /// The same for a single difference, which is feasible for larger words.
    fn collision_rate(outcome: Outcome, width: u32, da: u64, db: u64) -> f64 {
        let size = 1_u64 << width;
        let mut collisions = 0_u64;
        for x in 0..size {
            for y in 0..size {
                let a = outcome(product_halves(x, y, width), width);
                let b = outcome(product_halves(x ^ da, y ^ db, width), width);
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

    /// `combine` puts each half of the product in a word of its own, and what it does to each can be undone. So two
    /// blocks leave the buffer in the same state exactly when both halves are the same.
    fn both_halves([low, high]: [u64; 2], width: u32) -> u64 {
        high << width | low
    }

    /// Checks every possible difference between two blocks, so that no pattern (like the complement in issue #292,
    /// which collided 2^38 times more often than ideal at 64 bits) can stand out.
    /// (The worst measured is 1.6 times ideal.)
    #[test]
    fn test_no_block_difference_collides_often() {
        let width = 8;
        let profile = difference_profile(both_halves, width);
        let (rate, da, db) = worst(&profile, width, |_, _| true);
        assert!(
            rate < 3.0,
            "A difference of {:x?} collides {} times more often than ideal",
            (da, db),
            rate
        );
    }

    /// `AHasherStr` xors the halves of a product of two operands which both depend on the input, for strings of
    /// up to 8 bytes. But there the input only reaches the low half of each operand. Check that no difference
    /// which is confined to the low halves stands out, or grows with the word size the way the complement did.
    #[test]
    fn test_short_string_differences_do_not_scale() {
        let width = 8;
        let half = mask(width / 2);
        let profile = difference_profile(fold, width);
        let (rate, da, db) = worst(&profile, width, |da, db| da <= half && db <= half);
        assert!(rate < 6.0, "{:x?} {}", (da, db), rate);
        let width = 12;
        let half = mask(width / 2);
        for (da, db) in [(half, half), (half, 0), (0, half)] {
            let rate = collision_rate(fold, width, da, db);
            assert!(rate < 6.0, "{:x?} {}", (da, db), rate);
        }
    }

    /// splitmix64.
    fn random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let z = (*state ^ (*state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        let z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// How often two inputs of `between + 2` blocks leave the model of the buffer in the same state, when every
    /// block has the same second word, and the first word of the first block differs in bit `first` and that of
    /// the last block in bit `last`. With `stepped` the keys change after each block, as they do in `hash_in`.
    fn shared_word_rate(width: u32, between: usize, first: u32, last: u32, stepped: bool) -> f64 {
        let samples = 1_u64 << (width + 5);
        let mut seed = (first as u64) << 32 | (last as u64) << 16 | between as u64;
        let mut next = || random(&mut seed) & mask(width);
        let mut collisions = 0;
        for _ in 0..samples {
            let start = [next(), next()];
            let (mut keys, shared) = ([next(), next()], next());
            let increments = if stepped { [next() | 1, next() | 1] } else { [0, 0] };
            let mut buffers = [start, start];
            for block in 0..between + 2 {
                let word = next();
                let flipped = match block {
                    0 => word ^ 1 << first,
                    b if b == between + 1 => word ^ 1 << last,
                    _ => word,
                };
                for (buffer, word) in buffers.iter_mut().zip([word, flipped]) {
                    *buffer = combine(*buffer, [word ^ keys[0], shared ^ keys[1]], width);
                }
                keys = [
                    keys[0].wrapping_add(increments[0]) & mask(width),
                    keys[1].wrapping_add(increments[1]) & mask(width),
                ];
            }
            collisions += (buffers[0] == buffers[1]) as u64;
        }
        collisions as f64 / samples as f64 * (1_u64 << width) as f64
    }

    /// The worst of `shared_word_rate` over every pair of bits.
    fn worst_shared_word_rate(width: u32, between: usize, stepped: bool) -> (f64, u32, u32) {
        let mut worst = (0.0, 0, 0);
        for first in 0..width {
            for last in 0..width {
                let rate = shared_word_rate(width, between, first, last, stepped);
                if rate > worst.0 {
                    worst = (rate, first, last);
                }
            }
        }
        worst
    }

    /// Blocks with a word in common would give a multiply the same operand, if the keys stayed the same. When
    /// that operand ends in zeros, a later block can remove the difference an earlier one made, and with the
    /// product this gets more likely as the words get longer. Check that it does not happen with keys which
    /// change, and that this test would notice if it did.
    /// (With keys which change the worst measured is 0.6 times ideal. With the same keys for every block it is
    /// at 8 and 16 times ideal for 8 and 12 bit words.)
    #[test]
    fn test_blocks_which_share_a_word_do_not_cancel() {
        for width in [8, 12] {
            for between in [0, 1] {
                let (rate, first, last) = worst_shared_word_rate(width, between, true);
                assert!(
                    rate < 2.0,
                    "At {} bits a difference in bit {} and then, {} blocks later, bit {} collides {} times more often than ideal",
                    width,
                    first,
                    between + 1,
                    last,
                    rate
                );
            }
        }
        let (rate, _, _) = worst_shared_word_rate(12, 1, false);
        assert!(
            rate > 8.0,
            "With the same keys for every block the rate was only {}",
            rate
        );
    }

    /// The same on the real function, for the likeliest case which is known: Three blocks, of which the first
    /// differs in bit 63 of its first word and the last in bit 24. This needs a key which makes the operand they
    /// have in common end in around 32 zeros, so the keys here are chosen to. Of those, about one in 700 collides
    /// if the keys stay the same (which comes to one key in `2^41.5` over all), and none should if they change.
    #[test]
    fn test_blocks_which_share_a_word_at_full_width() {
        let samples = 1_u64 << 18;
        for stepped in [false, true] {
            let mut seed = 1;
            let mut collisions = 0;
            for _ in 0..samples {
                let key1 = (random(&mut seed) as u128) << 64 | random(&mut seed) as u128;
                let key2 = (random(&mut seed) as u128) << 64 | random(&mut seed) as u128;
                let mut hasher = AHasher::test_with_keys(key1, key2);
                if !stepped {
                    hasher.increments = [0, 0];
                }
                let shared = hasher.keys[1] ^ random(&mut seed) << 32;
                let mut hashers = [hasher.clone(), hasher];
                for flip in [1 << 63, 0, 1 << 24] {
                    let word = random(&mut seed);
                    hashers[0].hash_in([word, shared].convert());
                    hashers[1].hash_in([word ^ flip, shared].convert());
                }
                collisions += (hashers[0].buffer == hashers[1].buffer) as u64;
            }
            if stepped {
                assert_eq!(0, collisions);
            } else {
                assert!(
                    collisions > 100,
                    "With the same keys for every block there were only {}",
                    collisions
                );
            }
        }
    }
}
