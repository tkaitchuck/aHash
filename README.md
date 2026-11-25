# aHash     ![Build Status](https://img.shields.io/github/actions/workflow/status/tkaitchuck/aHash/rust.yml?branch=master) ![Licence](https://img.shields.io/crates/l/ahash) ![Downloads](https://img.shields.io/crates/d/ahash) 

AHash is a [fast](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#speed),
[DOS resistant](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#dos-resistance) hash for Rust.
For typical keys it computes a hash 5 to 9 times faster than the default hasher of the standard library.
AHash is intended *exclusively* for use in in-memory hashmaps.

AHash's output is of [high quality](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#quality) but aHash is **not** a cryptographically secure hash.

**AHash is not a fixed algorithm.** What it offers is a set of properties: Speed, quality, and resistance to DOS attacks.
The algorithm which provides them is subject to change. It depends on the CPU and on how the program is compiled, and
it is changed when a faster technique is found, or a flaw. This is how aHash keeps its speed and its quality over time.
It also means that the hash of a value is not the same on different computers, in different versions of aHash, or in
different builds of the same program.

## Design

Because AHash is a keyed hash, each map will produce completely different hashes, which cannot be predicted without knowing the keys.
[This prevents DOS attacks where an attacker sends a large number of items whose hashes collide that get used as keys in a hashmap.](https://github.com/tkaitchuck/aHash/blob/master/FAQ.md#how-does-ahash-prevent-dos-attacks)

This also avoids [accidentally quadratic behavior by reading from one map and writing to another.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

AHash has two algorithms. One uses the hardware AES instructions, and the other (the fallback) uses multiplication.
**Which one is used is decided when your program is compiled.** AES is used if the target has it enabled, which most
targets do not by default. (`aarch64-apple-darwin` is one which does.) To use it elsewhere, compile with
`RUSTFLAGS="-C target-cpu=native"` or `-C target-feature=+aes`. AES is supported on x86, x86-64 and AArch64.

AES is faster for strings: More than three times as fast at 1KB. Integers take the same time with both.

Both keep a small state of fixed size: 48 bytes with AES and 32 with the fallback, whatever the length of the input.
Nothing is allocated for a map or for a hash, and there are no lookup tables.

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

For typical keys, strings of 5 to 32 bytes, aHash computes a hash 8 to 9 times faster than SipHash-1-3 with AES, and
5 to 6 times faster with the fallback.

AHash is not the fastest hasher for small keys. Several are faster, among them
[rustc-hash](https://github.com/rust-lang/rustc-hash) (FxHash) and [foldhash](https://github.com/orlp/foldhash) as it
is used by default. They do not pass the [SMHasher3](https://gitlab.com/fwojcik/smhasher3) test suite, and are in the
second panel of the chart.
[The comparison](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#why-use-ahash-over-x) goes into
what the differences are, and has the details of how this was measured.

## Hash quality

AHash passes every test of [SMHasher3](https://gitlab.com/fwojcik/smhasher3), both with AES and with the fallback.
The code to reproduce the result, and the full output [are checked into the repo](https://github.com/tkaitchuck/aHash/tree/master/smhasher).

AHash regards this as the least that a hasher for general use should do. A library hashes whatever its callers give
it, and a hasher which fails has some kind of input for which its output is measurably not random. Such a hasher can
still be the right choice in a program whose author knows the algorithm and knows what the keys look like, but it is
not a sound default. [More on this here.](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md#quality)

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
