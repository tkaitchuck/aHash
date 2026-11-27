# aHash     ![Build Status](https://img.shields.io/github/actions/workflow/status/tkaitchuck/aHash/rust.yml?branch=master) ![Licence](https://img.shields.io/crates/l/ahash) ![Downloads](https://img.shields.io/crates/d/ahash) 

AHash is an ultra [fast](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#speed),
[DOS resistant](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#dos-resistance) hash written in Rust. It is intended *exclusively* for use in in-memory hashmaps.
For typical keys it computes a hash 5-10x faster than the default hasher in the standard library.

AHash's output is of [high quality](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#quality) but aHash is **not** a cryptographically secure hash.

**AHash's algorithm is not fixed.** How it computes the hash is dependent on the CPU it is running on, how the program
was compiled, and the version of the software it is running. If a flaw or faster hashing technique is found newer
versions of aHash will change the output hash value for a given input. Because the output is not the same on different 
computers, in different versions of aHash, or in different builds of the same program, aHash should not be used to 
persist hashs or in a situation where different hosts need to compute the same hash.
## Design

Because AHash is a keyed hash, each map will produce completely different hashes, which cannot be predicted without knowing the keys.
[This prevents DOS attacks where an attacker sends a large number of items whose hashes collide that get used as keys in a hashmap.](https://github.com/tkaitchuck/aHash/blob/master/FAQ.md#how-does-ahash-prevent-dos-attacks)

This also avoids [accidentally quadratic behavior by reading from one map and writing to another.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

AHash's primary algorithm uses the hardware AES instructions. It has a fallback (if the instruction is not available)
which uses multiplication.

AES is used if the target has it enabled, which most targets do not by default. (`aarch64-apple-darwin` is one which does.)
To use it elsewhere, compile with `RUSTFLAGS="-C target-cpu=native"` or `-C target-feature=+aes`.
AES is supported on x86, x86-64 and AArch64.

Having AES makes strings much faster. For hashing integers there is no meaningful difference.

The "`BuildHasher`" Which is held by the map holds onto 32 bytes of memory.

## Goals and Non-Goals

AHash does *not* have a fixed standard for its output. This allows it to improve over time. For example,
if any faster algorithm is found, aHash will be updated to incorporate the technique.
Similarly, should any flaw in aHash's DOS resistance be found, aHash will be changed to correct the flaw.
So it is important to use an up to date version.

Because it does not have a fixed standard, different computers or computers on different versions of the code will observe different hash values.
As such, aHash is not recommended for use other than in-memory maps. Specifically, aHash is not intended for network use or in applications which persist hashed values.
(In these cases `HighwayHash` would be a better choice)

Additionally, aHash is not intended to be cryptographically secure and should not be used as a MAC, or anywhere which requires a cryptographically secure hash.
(In these cases `SHA-3` would be a better choice)

## Usage

AHash is a drop in replacement for the default implementation of the `Hasher` trait. To construct a `HashMap` using aHash 
as its hasher do the following:

```rust
use ahash::RandomState;
use std::collections::HashMap;

let mut map: HashMap<i32, i32, RandomState> = HashMap::default();
map.insert(12, 34);
```
For convenience, wrappers called `AHashMap` and `AHashSet` are also provided.
These do the same thing with slightly less typing.
```rust
use ahash::AHashMap;

let mut map: AHashMap<i32, i32> = AHashMap::new();
map.insert(12, 34);
map.insert(56, 78);
```
There are also type aliases, for code which needs the map to be a `std::collections::HashMap`:
```rust
use ahash::{HashMap, HashMapExt};

let mut map: HashMap<i32, i32> = HashMap::new();
map.insert(12, 34);
```

## Flags

The aHash package has the following flags:
* `std`: This enables features which require the standard library. (On by default) This includes providing the utility classes `AHashMap` and `AHashSet`.
* `serde`: Enables `serde` support for `RandomState` and for the utility classes `AHashMap` and `AHashSet`.
* `runtime-rng`: To obtain a seed for Hashers will obtain randomness from the operating system. (On by default)
This is done using the [getrandom](https://github.com/rust-random/getrandom) crate.
* `compile-time-rng`: For OS targets without access to a random number generator, `compile-time-rng` provides an alternative.
If `getrandom` is unavailable and `compile-time-rng` is enabled, aHash will generate random numbers at compile time and embed them in the binary.
This allows for DOS resistance even if there is no random number generator available at runtime (assuming the compiled binary is not public).
This makes the binary non-deterministic. (If non-determinism is a problem see [constrandom's documentation](https://github.com/tkaitchuck/constrandom#deterministic-builds))
* `no-rng`: Do not use any random number generator, at compile time or at runtime. Unless the application supplies seeds, the keys are then
fixed constants combined with memory addresses, which is weak. This does nothing if `runtime-rng` or `compile-time-rng` is enabled.
* `atomic-polyfill`: For targets which lack `core::sync::atomic::AtomicUsize`. This uses the `portable-atomic` crate in its place.
* `nightly-arm-aes`: To use AES instructions on 32-bit ARM, which requires nightly. This is not needed on AArch64.

If both `runtime-rng` and `compile-time-rng` are enabled the `runtime-rng` will take precedence and `compile-time-rng` will do nothing.
If neither flag is set, seeds can be supplied by the application. [Multiple apis](https://docs.rs/ahash/latest/ahash/random_state/struct.RandomState.html)
are available to do this.

On a nightly compiler aHash also uses specialization, to hash integers faster. This needs no flag.

## Comparison with other hashers

A full comparison with other hashing algorithms can be found [here](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md).

![Speed of hashing a string by its length, for each hasher](compare/speed.svg)

The time to compute one hash, in nanoseconds. (On an AMD Ryzen AI 9 465, compiled with `-C target-cpu=native`.)

| Hasher | u64 | 15 byte string | 1023 byte string |
|---|---:|---:|---:|
| aHash (AES) | 0.51 | 0.94 | 10.4 |
| aHash (fallback) | 0.51 | 1.35 | 36.9 |
| SipHash-1-3 (the default of `std`) | 7.15 | 8.67 | 137 |

A typical hashmap lookup takes about 1 ns on top of this, independent of the hashing algorithm.

## Hash quality

AHash passes every test of [SMHasher3](https://gitlab.com/fwojcik/smhasher3), both with AES and with the fallback.
The code to reproduce the result, and the full output [are checked into the repo](https://github.com/tkaitchuck/aHash/tree/master/smhasher).

## Additional FAQ

A separate FAQ document is maintained [here](https://github.com/tkaitchuck/aHash/blob/master/FAQ.md). 
If you have questions not covered there, open an issue [here](https://github.com/tkaitchuck/aHash/issues).

## License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
