//! Tests of properties the AES hasher is meant to have, each over many keys:
//! * Inputs which differ in the ways that are cheapest to cancel never collide.
//! * Inputs which only differ in length never collide.
//! * Each bit of the output, and each pair of bits, changes half of the time when any bit of the input or of the
//!   keys does.
#![cfg(any(
    all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)),
    all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
    all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
))]

use crate::aes_hash::AHasher;
use crate::operations::*;
use core::convert::TryInto;
use core::hash::Hasher;

type Block = [u8; 16];

/// Multiplication in the field AES uses.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    result
}

/// The part of a round after the S-box (with no key): Each byte moves to a column which depends on its row,
/// and then each column is multiplied by a matrix. Byte `i` is in row `i % 4` of column `i / 4`.
fn linear_layer(state: Block, inverse: bool) -> Block {
    let matrix: [u8; 4] = if inverse { [14, 11, 13, 9] } else { [2, 3, 1, 1] };
    let mut shifted = [0_u8; 16];
    for column in 0..4 {
        for row in 0..4 {
            let from = if inverse {
                (column + 4 - row) % 4
            } else {
                (column + row) % 4
            };
            shifted[row + 4 * column] = state[row + 4 * from];
        }
    }
    let mut result = [0_u8; 16];
    for column in 0..4 {
        for row in 0..4 {
            for k in 0..4 {
                result[row + 4 * column] ^= gf_mul(matrix[(k + 4 - row) % 4], shifted[k + 4 * column]);
            }
        }
    }
    result
}

/// A small deterministic generator (splitmix64).
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_u128(&mut self) -> u128 {
        (self.next() as u128) << 64 | self.next() as u128
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn nonzero_byte(&mut self) -> u8 {
        (self.next() % 255) as u8 + 1
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn hash_bytes(key1: u128, key2: u128, data: &[u8]) -> u64 {
    let mut hasher = AHasher::test_with_keys(key1, key2);
    hasher.write(data);
    hasher.finish()
}

/// [linear_layer] is what a round does to a difference in one byte, once the S-box has chosen which difference.
/// (The tests which construct canceling differences rely on it.)
#[test]
fn test_linear_layer_matches_a_round() {
    let mut random = Random(1);
    for position in 0..16 {
        let state = random.next_u128();
        let mut changed = state.to_ne_bytes();
        changed[position] ^= random.nonzero_byte();
        let changed = u128::from_ne_bytes(changed);
        let differences = [
            (false, aesenc(state, 0) ^ aesenc(changed, 0)),
            (true, aesdec(state, 0) ^ aesdec(changed, 0)),
        ];
        for (inverse, difference) in differences {
            let matches = (1..=255_u8).filter(|&sbox_output| {
                let mut before = [0_u8; 16];
                before[position] = sbox_output;
                linear_layer(before, inverse) == difference.to_ne_bytes()
            });
            assert_eq!(1, matches.count(), "Byte {} inverse {}", position, inverse);
        }
    }
}

/// The lengths at which something changes, and some in between.
fn interesting_lengths() -> Vec<usize> {
    let mut lengths: Vec<usize> = (1..=34).collect();
    lengths.extend([47, 48, 49, 63, 64, 65, 66, 80, 96, 97, 127, 128, 129, 130, 131]);
    // (A long input is read as its last 128 bytes, and before that 128 bytes at a time from the start.)
    lengths.extend([
        157, 158, 159, 160, 161, 189, 190, 191, 192, 193, 221, 222, 223, 224, 225,
    ]);
    lengths.extend([
        253, 254, 255, 256, 257, 258, 285, 286, 287, 288, 300, 383, 384, 385, 386, 420, 512, 513,
    ]);
    lengths
}

/// Inputs which differ in only one or two bytes never have the same hash.
///
/// Such inputs are the ones for which the fewest things have to go right for the difference to cancel out. So if
/// some structure allowed that to happen cheaply, this is where it would show up. Each pair is tried with a
/// number of keys, so that something which only works for one key in a few hundred thousand would be noticed.
#[test]
fn test_no_collisions_from_small_differences() {
    let mut random = Random(4);
    let distances = [
        1, 2, 3, 14, 15, 16, 17, 18, 30, 32, 34, 48, 62, 64, 66, 96, 126, 128, 130,
    ];
    let mut pairs_tested = 0_u64;
    for len in interesting_lengths() {
        for _ in 0..16 {
            let (key1, key2) = (random.next_u128(), random.next_u128());
            let base = random.bytes(len);
            let expected = hash_bytes(key1, key2, &base);
            let mut changed = base.clone();
            for position in 0..len {
                changed[position] ^= random.nonzero_byte();
                assert_ne!(
                    expected,
                    hash_bytes(key1, key2, &changed),
                    "Byte {} of {}",
                    position,
                    len
                );
                pairs_tested += 1;
                for distance in distances {
                    if position + distance < len {
                        changed[position + distance] ^= random.nonzero_byte();
                        assert_ne!(
                            expected,
                            hash_bytes(key1, key2, &changed),
                            "Bytes {} and {} of {}",
                            position,
                            position + distance,
                            len
                        );
                        changed[position + distance] = base[position + distance];
                        pairs_tested += 1;
                    }
                }
                changed[position] = base[position];
            }
        }
    }
    assert!(pairs_tested > 1_000_000);
}

/// A difference in one byte of a block cannot be canceled by a difference in the block which follows it.
///
/// This is the form of the collisions in issue #292. After a round, a difference in one byte has become a
/// difference in the four bytes of one column, and which difference it is depends only on what the S-box did
/// to that byte, for which there are 255 possibilities. If the next block's only role were to be xored with the
/// result, one of those 255 would cancel it. So for a function with that weakness, this finds a collision for
/// every key, position and difference it tries. Here the first difference has also reached other parts of
/// the state by then, so none of them should work for any key.
#[test]
fn test_no_collisions_from_canceling_one_byte() {
    let mut random = Random(5);
    // (length, where the blocks start, where they end, distance to the block which is read into the same lane next)
    let cases = [
        (32, 0, 32, 16),
        (48, 0, 32, 16),
        (64, 0, 64, 16),
        (128, 0, 128, 16),
        (128, 0, 128, 64),
        // (In a long input the same lane receives blocks which start 31, 97 and 128 bytes apart.)
        (420, 1, 420 - 128, 31),
        (420, 0, 420 - 128, 97),
        (700, 1, 700 - 128, 31),
        (700, 0, 700 - 128, 97),
        (700, 0, 700 - 128, 128),
    ];
    for (len, start, end, distance) in cases {
        for _ in 0..8 {
            let (key1, key2) = (random.next_u128(), random.next_u128());
            let base = random.bytes(len);
            let expected = hash_bytes(key1, key2, &base);
            for _ in 0..4 {
                let block = start + 16 * random.below((end - start - distance) / 16);
                let byte = random.below(16);
                let mut changed = base.clone();
                changed[block + byte] ^= random.nonzero_byte();
                for inverse in [false, true] {
                    for sbox_output in 1..=255_u8 {
                        let mut difference = [0_u8; 16];
                        difference[byte] = sbox_output;
                        let difference = linear_layer(difference, inverse);
                        let mut canceled = changed.clone();
                        for i in 0..16 {
                            canceled[block + distance + i] ^= difference[i];
                        }
                        assert_ne!(
                            expected,
                            hash_bytes(key1, key2, &canceled),
                            "Length {} byte {} of the block at {}",
                            len,
                            byte,
                            block
                        );
                    }
                }
            }
        }
    }
    // The same for values supplied one at a time.
    for _ in 0..64 {
        let (key1, key2) = (random.next_u128(), random.next_u128());
        let (first, second) = (random.next_u128(), random.next_u128());
        let hash = |first: u128, second: u128| {
            let mut hasher = AHasher::test_with_keys(key1, key2);
            hasher.write_u128(first);
            hasher.write_u128(second);
            hasher.finish()
        };
        let expected = hash(first, second);
        let byte = random.below(16);
        let mut difference = [0_u8; 16];
        difference[byte] = random.nonzero_byte();
        let changed = first ^ u128::from_ne_bytes(difference);
        for inverse in [false, true] {
            for sbox_output in 1..=255_u8 {
                let mut difference = [0_u8; 16];
                difference[byte] = sbox_output;
                let difference = u128::from_ne_bytes(linear_layer(difference, inverse));
                assert_ne!(expected, hash(changed, second ^ difference));
            }
        }
    }
}

/// Inputs which only differ in their length never have the same hash.
///
/// Up to 16 bytes are packed into one value, and the same value can come from more than one length. (For example
/// any number of zeros.) Then only the length tells them apart. The same goes for longer runs of one byte: Every
/// read of them returns the same thing, and above 128 bytes the number of reads only changes every 128.
///
/// A slice is hashed as its length followed by its contents, so the length is supplied twice: Once as a value,
/// and once by `write`. These must not be able to cancel each other out, as they would if both went into the
/// same state.
///
/// This has to hold for every key, including the simplest ones.
#[test]
fn test_no_collisions_between_lengths() {
    let mut random = Random(14);
    let patterns: [&[u8]; 5] = [&[0], &[0xff], &[1], &[0, 1], &[7, 0, 0, 0]];
    let lengths: Vec<usize> = (0..=40)
        .chain([63, 64, 65, 100, 127, 128, 129, 130, 131, 160, 200, 255, 256, 257, 258, 300, 384, 385, 500])
        .collect();
    let mut keys: Vec<(u128, u128)> = vec![(0, 0), (1, 0), (0, 1), (12345, 67890), (1 << 64, 1 << 64), (u128::MAX, 0)];
    keys.extend((0..250).map(|_| (random.next_u128(), random.next_u128())));
    for (key1, key2) in keys {
        for with_prefix in [false, true] {
            for pattern in patterns {
                let mut hashes: Vec<u64> = lengths
                    .iter()
                    .map(|&len| {
                        let data: Vec<u8> = pattern.iter().cycle().take(len).copied().collect();
                        let mut hasher = AHasher::test_with_keys(key1, key2);
                        if with_prefix {
                            hasher.write_usize(len);
                        }
                        hasher.write(&data);
                        hasher.finish()
                    })
                    .collect();
                hashes.sort_unstable();
                hashes.dedup();
                assert_eq!(lengths.len(), hashes.len(), "Lengths of {:?} collide", pattern);
            }
        }
    }
}

/// The length of a slice cannot be canceled by a difference in its contents.
///
/// A slice is hashed as its length followed by its contents. Two lengths differ in one byte, so after a round
/// they differ in one column, in one of 255 ways. Contents which differ in just that way remove the difference
/// from the state the values go into. The hashes must still be different, because of where else the length
/// went.
#[test]
fn test_no_collisions_from_canceling_the_length() {
    let mut random = Random(17);
    // (Enough keys that this would fail even if it only worked for one key and pair of lengths in several thousand.)
    for _ in 0..2048 {
        let (key1, key2) = (random.next_u128(), random.next_u128());
        let (start, fill) = (random.bytes(4), random.next() as u8);
        // (From 12 bytes up the first four bytes are only read once, and these all read as the same value.)
        let slice = |len: usize, difference: Block| -> u64 {
            let mut data = vec![fill; len];
            for i in 0..4 {
                data[i] = start[i] ^ difference[i];
            }
            let mut hasher = AHasher::test_with_keys(key1, key2);
            hasher.write_usize(len);
            hasher.write(&data);
            hasher.finish()
        };
        for first in 12..=16 {
            let expected = slice(first, [0; 16]);
            for second in first + 1..=16 {
                for sbox_output in 1..=255_u8 {
                    let mut difference = [0_u8; 16];
                    difference[0] = sbox_output;
                    let difference = linear_layer(difference, false);
                    assert_ne!(
                        expected,
                        slice(second, difference),
                        "Lengths {} and {}",
                        first,
                        second
                    );
                }
            }
        }
    }
}

/// Measures how far the output is from changing at random when the input changes.
///
/// `hash` is given a key and an input of `input_bits` bits, as a vector of bytes. For each of the bits in
/// `flipped`, and each of `trials` random keys and inputs, the input is hashed with and without that bit flipped.
///
/// Returns the largest amount by which the following differ from one half, over all of the bits flipped:
/// * The fraction of trials in which a bit of the output changed.
/// * The fraction of trials in which exactly one of a pair of bits of the output changed. (If `pairs` is set.)
///
/// (The second is not implied by the first: If a round is missing from the end, there are pairs of bits which
/// each change half the time, but always together.)
fn avalanche(
    hash: impl Fn(u128, u128, &[u8]) -> u64,
    input_bytes: usize,
    flipped: &[usize],
    trials: u32,
    pairs: bool,
    seed: u64,
) -> (f64, f64) {
    assert!(trials < 1 << COUNTER_BITS);
    let mut random = Random(seed);
    let mut single = vec![[0_u64; COUNTER_BITS]; flipped.len()];
    let mut pair = vec![[0_u64; COUNTER_BITS]; flipped.len() * 64];
    for _ in 0..trials {
        let (key1, key2) = (random.next_u128(), random.next_u128());
        let mut input = random.bytes(input_bytes);
        let expected = hash(key1, key2, &input);
        for (index, &bit) in flipped.iter().enumerate() {
            input[bit / 8] ^= 1 << (bit % 8);
            let difference = hash(key1, key2, &input) ^ expected;
            input[bit / 8] ^= 1 << (bit % 8);
            count(&mut single[index], difference);
            for j in 0..if pairs { 64 } else { 0 } {
                // Bit k of this is set if exactly one of bits j and k changed.
                let one_changed = difference ^ 0_u64.wrapping_sub(difference >> j & 1);
                count(&mut pair[index * 64 + j], one_changed);
            }
        }
    }
    let bias = |counters: &[u64; COUNTER_BITS], bit: usize| (total(counters, bit) as f64 / trials as f64 - 0.5).abs();
    let mut worst_single: f64 = 0.0;
    let mut worst_pair: f64 = 0.0;
    for index in 0..flipped.len() {
        for j in 0..64 {
            worst_single = worst_single.max(bias(&single[index], j));
            for k in j + 1..64 {
                worst_pair = worst_pair.max(bias(&pair[index * 64 + j], k));
            }
        }
    }
    (worst_single, worst_pair)
}

/// 64 counters, one for each bit of a word, stored as the bits of their values: Bit `i` of `counters[n]` is
/// bit `n` of the count for bit `i`. (This allows all 64 to be incremented at once.)
const COUNTER_BITS: usize = 18;

/// Adds one to the counter of each bit which is set in `bits`.
fn count(counters: &mut [u64; COUNTER_BITS], bits: u64) {
    let mut carry = bits;
    for counter in counters.iter_mut() {
        let sum = *counter ^ carry;
        carry &= *counter;
        *counter = sum;
        if carry == 0 {
            break;
        }
    }
}

fn total(counters: &[u64; COUNTER_BITS], bit: usize) -> u32 {
    (0..COUNTER_BITS).map(|n| ((counters[n] >> bit & 1) as u32) << n).sum()
}

/// Returns `count` distinct bits of an input of `bytes` bytes: Those at the start and the end, and those where
/// the way a long input is read changes, and then others at random.
fn sample_bits(bytes: usize, count: usize, random: &mut Random) -> Vec<usize> {
    let mut bits = Vec::new();
    for position in [
        0,
        1,
        2,
        bytes - 1,
        bytes.saturating_sub(2),
        15,
        16,
        30,
        31,
        32,
        33,
        bytes / 2,
    ] {
        let bit = 8 * position + random.below(8);
        if position < bytes && !bits.contains(&bit) {
            bits.push(bit);
        }
    }
    while bits.len() < count.min(8 * bytes) {
        let bit = random.below(8 * bytes);
        if !bits.contains(&bit) {
            bits.push(bit);
        }
    }
    bits.truncate(count);
    bits
}

/// Each bit of a single `u64` changes each bit of the output half of the time, as closely as can be measured.
///
/// This has the least between the input and the output: Only the rounds of `finish`. It needs all three of
/// them. With two, the largest bias here is 0.012.
#[test]
fn test_avalanche_of_u64() {
    let hash = |key1: u128, key2: u128, input: &[u8]| {
        let mut hasher = AHasher::test_with_keys(key1, key2);
        hasher.write_u64(u64::from_ne_bytes(input.try_into().unwrap()));
        hasher.finish()
    };
    let all_bits: Vec<usize> = (0..64).collect();
    // The largest of 4096 measurements over 65536 trials is expected to be about 0.0075.
    let (single, _) = avalanche(hash, 8, &all_bits, 1 << 16, false, 6);
    assert!(single < 0.01, "Bias of {}", single);
    // The largest of 129024 measurements over 8192 trials is expected to be about 0.025.
    let (_, pair) = avalanche(hash, 8, &all_bits, 1 << 13, true, 7);
    assert!(pair < 0.035, "Bias of {} between pairs of bits", pair);
}

/// As above for values supplied in other ways.
#[test]
fn test_avalanche_of_fixed_size_values() {
    let mut random = Random(8);
    let hash_u128 = |key1: u128, key2: u128, input: &[u8]| {
        let mut hasher = AHasher::test_with_keys(key1, key2);
        hasher.write_u128(u128::from_ne_bytes(input.try_into().unwrap()));
        hasher.finish()
    };
    let hash_words = |key1: u128, key2: u128, input: &[u8]| {
        let mut hasher = AHasher::test_with_keys(key1, key2);
        for word in input.chunks(8) {
            hasher.write_u64(u64::from_ne_bytes(word.try_into().unwrap()));
        }
        hasher.finish()
    };
    let (single, pair) = avalanche(hash_u128, 16, &sample_bits(16, 32, &mut random), 1 << 12, true, 9);
    assert!(single < 0.045 && pair < 0.05, "u128: Bias of {} and {}", single, pair);
    #[cfg(specialize)]
    {
        let hash_fixed = |key1: u128, key2: u128, input: &[u8]| {
            let mut hasher = crate::aes_hash::AHasherFixed(AHasher::test_with_keys(key1, key2));
            hasher.write_u128(u128::from_ne_bytes(input.try_into().unwrap()));
            hasher.finish()
        };
        let all_bits: Vec<usize> = (0..128).collect();
        let (single, pair) = avalanche(hash_fixed, 16, &all_bits, 1 << 12, true, 16);
        assert!(single < 0.045 && pair < 0.05, "Fixed size: Bias of {} and {}", single, pair);
    }
    for words in 2..=5 {
        let bits = sample_bits(8 * words, 32, &mut random);
        let (single, pair) = avalanche(hash_words, 8 * words, &bits, 1 << 12, true, 10);
        assert!(
            single < 0.045 && pair < 0.05,
            "{} words: Bias of {} and {}",
            words,
            single,
            pair
        );
    }
}

/// Each bit of the keys changes each bit of the output half of the time, whatever is hashed.
#[test]
fn test_avalanche_of_keys() {
    let mut random = Random(18);
    let message = random.bytes(200);
    for len in [0, 4, 24, 100, 200] {
        // (The keys are supplied as the input, and the input is fixed.)
        let hash = |_: u128, _: u128, keys: &[u8]| {
            let key1 = u128::from_ne_bytes(keys[..16].try_into().unwrap());
            let key2 = u128::from_ne_bytes(keys[16..].try_into().unwrap());
            let mut hasher = AHasher::test_with_keys(key1, key2);
            if len == 0 {
                hasher.write_u64(1);
            } else {
                hasher.write(&message[..len]);
            }
            hasher.finish()
        };
        let bits: Vec<usize> = if len <= 4 {
            (0..256).collect()
        } else {
            sample_bits(32, 64, &mut random)
        };
        let (single, pair) = avalanche(hash, 32, &bits, 1 << 12, true, 19);
        assert!(
            single < 0.045 && pair < 0.05,
            "Length {}: Bias of {} and {}",
            len,
            single,
            pair
        );
    }
}

/// As above for byte strings of each kind of length.
#[test]
fn test_avalanche_of_bytes() {
    let mut random = Random(11);
    for len in [
        1, 2, 3, 4, 7, 8, 9, 16, 17, 32, 33, 64, 65, 128, 129, 158, 191, 300, 420,
    ] {
        let bits = sample_bits(len, 16, &mut random);
        let (single, pair) = avalanche(hash_bytes, len, &bits, 1 << 12, true, 12);
        assert!(
            single < 0.045 && pair < 0.05,
            "Length {}: Bias of {} and {}",
            len,
            single,
            pair
        );
    }
}

/// The length is mixed in as thoroughly as the data.
///
/// Some inputs differ only in length as far as the hasher is concerned: Short runs of zeros of different
/// lengths are all read as the same value.
#[test]
fn test_avalanche_of_length() {
    let trials = 1 << 12;
    for (first, second) in [(0, 1), (1, 2), (3, 4), (0, 8), (5, 7)] {
        let mut random = Random(13);
        let mut single = [0_u32; 64];
        let mut pair = [[0_u32; 64]; 64];
        for _ in 0..trials {
            let (key1, key2) = (random.next_u128(), random.next_u128());
            let difference = hash_bytes(key1, key2, &[0; 8][..first]) ^ hash_bytes(key1, key2, &[0; 8][..second]);
            for j in 0..64 {
                let changed = difference >> j & 1;
                single[j] += changed as u32;
                let one_changed = difference ^ 0_u64.wrapping_sub(changed);
                for k in j + 1..64 {
                    pair[j][k] += (one_changed >> k & 1) as u32;
                }
            }
        }
        let bias = |count: u32| (count as f64 / trials as f64 - 0.5).abs();
        for j in 0..64 {
            assert!(bias(single[j]) < 0.045, "Lengths {} and {} bit {}", first, second, j);
            for k in j + 1..64 {
                assert!(
                    bias(pair[j][k]) < 0.05,
                    "Lengths {} and {} bits {} and {}",
                    first,
                    second,
                    j,
                    k
                );
            }
        }
    }
}
