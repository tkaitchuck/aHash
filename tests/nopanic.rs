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

// `RandomState<T>` picks its specialized path from `T`, so each path needs a state of that type.
#[inline(never)]
#[no_panic]
fn hash_one_strings(strings: &RandomState<String>, s: &str, string: String) -> [u64; 2] {
    [strings.hash_one(s), strings.hash_one(string)]
}

#[inline(never)]
#[no_panic]
fn hash_one_bytes(vecs: &RandomState<Vec<u8>>, bytes: &[u8], vec: Vec<u8>) -> [u64; 2] {
    [vecs.hash_one(bytes), vecs.hash_one(vec)]
}

struct IntStates {
    a: RandomState<u8>,
    b: RandomState<u32>,
    c: RandomState<u64>,
    d: RandomState<u128>,
    e: RandomState<usize>,
    f: RandomState<i64>,
}

#[inline(never)]
#[no_panic]
fn hash_one_ints(states: &IntStates, a: u8, b: u32, c: u64, d: u128, e: usize, f: i64) -> [u64; 6] {
    [
        states.a.hash_one(a),
        states.b.hash_one(b),
        states.c.hash_one(c),
        states.d.hash_one(d),
        states.e.hash_one(e),
        states.f.hash_one(f),
    ]
}

// The unspecialized path.
#[inline(never)]
#[no_panic]
fn hash_one_generic(state: &RandomState<()>, s: &str, bytes: &[u8], d: u128) -> [u64; 3] {
    [state.hash_one(s), state.hash_one(bytes), state.hash_one(d)]
}

#[test]
fn test_no_panic() {
    let state = RandomState::<()>::with_seeds(1, 2, 3, 4);
    let strings = RandomState::<String>::with_seeds(1, 2, 3, 4);
    let vecs = RandomState::<Vec<u8>>::with_seeds(1, 2, 3, 4);
    let ints = IntStates {
        a: RandomState::with_seeds(1, 2, 3, 4),
        b: RandomState::with_seeds(1, 2, 3, 4),
        c: RandomState::with_seeds(1, 2, 3, 4),
        d: RandomState::with_seeds(1, 2, 3, 4),
        e: RandomState::with_seeds(1, 2, 3, 4),
        f: RandomState::with_seeds(1, 2, 3, 4),
    };
    let text = "a string longer than the sixty four bytes covered by the largest single read";
    let bytes = text.as_bytes().to_vec();
    // Running is incidental; the check happened at link time.
    for len in 0..=bytes.len() {
        let b = black_box(&bytes[..len]);
        let s = black_box(&text[..len]);
        write_bytes(black_box(state.build_hasher()), b);
        hash_via_trait(black_box(state.build_hasher()), s, b, black_box(len as i32));
        hash_one_strings(black_box(&strings), s, black_box(text[..len].to_string()));
        hash_one_bytes(black_box(&vecs), b, black_box(bytes[..len].to_vec()));
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
    hash_one_ints(
        black_box(&ints),
        black_box(1),
        black_box(2),
        black_box(3),
        black_box(4),
        black_box(5),
        black_box(6),
    );
    hash_one_generic(black_box(&state), black_box(text), black_box(&bytes), black_box(7));
    write_bytes(black_box(AHasher::default()), black_box(&bytes));
}
