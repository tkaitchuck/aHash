//! Link-time proof that hashing cannot panic.
//!
//! `#[no_panic]` fails the link if any panic remains reachable from the annotated function after optimization.
//! Every input goes through `black_box` so LLVM cannot fold constants into these functions and delete the
//! branches for other input lengths; without that, a panic reachable only for some lengths would go unnoticed.
//! The hashers are built outside the checked functions because key generation is not what is under test.

use ahash::{AHasher, RandomState};
use no_panic::no_panic;
use std::hash::{BuildHasher, Hash, Hasher};
use std::hint::black_box;

#[inline(never)]
#[no_panic]
fn write_bytes(mut hasher: AHasher, bytes: &[u8]) -> u64 {
    hasher.write(bytes);
    hasher.finish()
}

#[inline(never)]
#[no_panic]
fn write_ints(mut hasher: AHasher, a: u8, b: u16, c: u32, d: u64, e: u128, f: usize) -> u64 {
    hasher.write_u8(a);
    hasher.write_u16(b);
    hasher.write_u32(c);
    hasher.write_u64(d);
    hasher.write_u128(e);
    hasher.write_usize(f);
    hasher.finish()
}

#[inline(never)]
#[no_panic]
fn hash_via_trait(mut hasher: AHasher, s: &str, bytes: &[u8], n: i32) -> u64 {
    s.hash(&mut hasher);
    bytes.hash(&mut hasher);
    n.hash(&mut hasher);
    hasher.finish()
}

// The specialized string hasher is reached only through owned `String` and `Vec<u8>`.
#[inline(never)]
#[no_panic]
fn hash_one_inherent(state: &RandomState, s: &str, bytes: &[u8], vec: Vec<u8>, string: String) -> [u64; 4] {
    [
        state.hash_one(s),
        state.hash_one(bytes),
        state.hash_one(vec),
        state.hash_one(string),
    ]
}

#[inline(never)]
#[no_panic]
fn hash_one_inherent_ints(state: &RandomState, a: u8, b: u32, c: u64, d: u128, e: usize, f: i64) -> [u64; 6] {
    [
        state.hash_one(a),
        state.hash_one(b),
        state.hash_one(c),
        state.hash_one(d),
        state.hash_one(e),
        state.hash_one(f),
    ]
}

#[inline(never)]
#[no_panic]
fn hash_one_trait(state: &RandomState, s: &str, bytes: &[u8], d: u128) -> [u64; 3] {
    [
        BuildHasher::hash_one(state, s),
        BuildHasher::hash_one(state, bytes),
        BuildHasher::hash_one(state, d),
    ]
}

#[test]
fn test_no_panic() {
    let state = RandomState::with_seeds(1, 2, 3, 4);
    let text = "a string longer than the sixty four bytes covered by the largest single read";
    let bytes = text.as_bytes().to_vec();
    // Running is incidental; the check happened at link time.
    for len in 0..=bytes.len() {
        let b = black_box(&bytes[..len]);
        let s = black_box(&text[..len]);
        write_bytes(black_box(state.build_hasher()), b);
        hash_via_trait(black_box(state.build_hasher()), s, b, black_box(len as i32));
        hash_one_inherent(
            black_box(&state),
            s,
            b,
            black_box(bytes[..len].to_vec()),
            black_box(text[..len].to_string()),
        );
    }
    write_ints(
        black_box(state.build_hasher()),
        black_box(1),
        black_box(2),
        black_box(3),
        black_box(4),
        black_box(5),
        black_box(6),
    );
    hash_one_inherent_ints(
        black_box(&state),
        black_box(1),
        black_box(2),
        black_box(3),
        black_box(4),
        black_box(5),
        black_box(6),
    );
    hash_one_trait(black_box(&state), black_box(text), black_box(&bytes), black_box(7));
    write_bytes(black_box(AHasher::default()), black_box(&bytes));
}
