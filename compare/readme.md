# Comparison with other hashers

![Speed of hashing a string by its length, for each hasher](speed.svg)

In short:

* aHash is **several times faster than SipHash-1-3**, the default hasher of the standard library. For typical keys,
  strings of 5 to 32 bytes, it computes a hash 8 to 9 times faster with AES, and 5 to 6 times faster with its fallback.
* aHash **passes SMHasher3**, which is [the least that a hasher for general use should do](#quality). Most of the
  hashers here do not. That includes the ones which are fastest for small keys:
  [rustc-hash](https://github.com/rust-lang/rustc-hash), and the *fast* variants of
  [foldhash](https://github.com/orlp/foldhash) and [rapidhash](https://github.com/hoxxep/rapidhash). The chart has
  the hashers which do not pass in a panel of their own.
* With AES, aHash is the fastest hasher here for strings of 255 bytes or more: About 80 GB per second for a long
  string.
* The closest alternatives are [foldhash and rapidhash](#foldhash-and-rapidhash), which are built on the same
  multiplication as aHash's fallback.

## What aHash offers

AHash is designed *exclusively* for use in in-memory hashmaps. **Its algorithm is not a standard, and is subject to
change.** What aHash offers, and keeps from one version to the next, is a set of properties:

* **It is keyed.** Every map gets its own random keys. The same value has a different hash in each map, and the hashes
  cannot be predicted without knowing the keys.
* **It is designed to resist DOS attacks.** An attacker who does not know the keys should not be able to construct
  inputs which collide, or to learn the keys from the hashes it can see. See [DOS resistance](#dos-resistance).
* **Its output is of high quality.** Each of the algorithms aHash uses is required to pass the full SMHasher3 test
  suite. See [Quality](#quality).
* **It is fast.** It uses what the CPU it is compiled for can do: The hardware AES instructions where they are enabled,
  and multiplication elsewhere.
* **Its memory use is small and fixed.** A `RandomState` is 32 bytes. A hasher is 48 bytes with AES and 32 with the
  fallback, whatever the length of the input. Nothing is allocated for a map or for a hash, there are no lookup
  tables, and input is not buffered.

The way aHash keeps these as hardware, compilers and the known attacks change is by adapting. Which algorithm is used
depends on the target CPU and on how the program is compiled, and the algorithms themselves change when a faster
technique is found, or a flaw.

The price of this is that **the hash of a value is not the same on different computers, in different versions of aHash,
or in different builds of the same program.** That is fine for a hashmap. It makes aHash inappropriate where a hash is
sent over a network or persisted. AHash is also not a cryptographic hash.

Hashers with a fixed standard cannot do this. They have to produce the same output everywhere, so they cannot use what
only some CPUs have, and a flaw in the algorithm cannot be fixed without becoming a different algorithm.

### Which algorithm is used

* If the [hardware AES instructions](https://en.wikipedia.org/wiki/AES_instruction_set) are enabled when the program
  is compiled, aHash uses them. This is supported on x86, x86-64 and AArch64. (And on 32-bit ARM, with a nightly
  compiler and the `nightly-arm-aes` feature.)
* Otherwise it falls back on an algorithm which is based on multiplication.

**The choice is made at compile time.** aHash does not detect the CPU when the program runs. Some targets, such as
`aarch64-apple-darwin`, enable AES by default. Most do not, including `x86_64-unknown-linux-gnu`. There the fallback is
used unless the program is compiled with `-C target-cpu=native`, or with `-C target-feature=+aes`, or for a CPU which
has AES.

## Speed

The hashers are in two groups: Those which pass SMHasher3 (see [Quality](#quality)), and those which do not. The best of
each column of each table is in bold.

The time to compute one hash, in nanoseconds. (Smaller is better) Hashers which pass SMHasher3:

| Hasher | u64 | 15 byte string | 1023 byte string |
|---|---:|---:|---:|
| **aHash** (AES) | **0.51** | 0.94 | **10.4** |
| **aHash** (fallback) | 0.51 | 1.35 | 36.9 |
| foldhash (quality) | 0.52 | **0.70** | 19.8 |
| rapidhash (quality) | 0.52 | 0.94 | 30.8 |
| SipHash-1-3 (std) | 7.15 | 8.67 | 137 |
| SipHash-2-4 | 5.75 | 10.1 | 239 |

**Note: A hashmap lookup takes about 1 ns on top of this, independent of the hashing algorithm.**


For comparison Hashers which do not pass SMHasher3. These are provided as reference but should be considered as specialized 
options and not used unless the structure of the data and how it interacts with the algorithm is understood:

| Hasher | u64 | 15 byte string | 1023 byte string |
|---|---:|---:|---:|
| foldhash (fast) | 0.41 | **0.63** | **18.9** |
| rustc-hash (FxHash 2) | 0.32 | 0.78 | 30.4 |
| rapidhash (fast) | 0.41 | 0.81 | 30.4 |
| fxhash (original FxHash) | **0.28** | 2.34 | 111 |
| fnv | 1.54 | 4.35 | 793 |
| xxh3 (xxhash-rust) | 5.37 | 11.3 | 33.3 |
| seahash | 3.78 | 11.3 | 87.6 |

The time to hash a string, by its length in bytes. (Smaller is better) Hashers which pass SMHasher3:

| Hasher | 1 | 3 | 7 | 15 | 31 | 63 | 127 | 255 | 511 | 1023 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **aHash** (AES) | 1.01 | 1.01 | 1.01 | 0.94 | **1.22** | **1.93** | 3.43 | **3.78** | **6.11** | **10.4** |
| **aHash** (fallback) | 1.48 | 1.49 | 1.42 | 1.35 | 2.15 | 3.07 | 5.04 | 9.17 | 17.8 | 36.9 |
| foldhash (quality) | **0.92** | **0.91** | **0.79** | **0.70** | 1.63 | 2.10 | **3.05** | 5.79 | 10.5 | 19.8 |
| rapidhash (quality) | 1.18 | 1.19 | 0.99 | 0.94 | 1.58 | 3.23 | 4.17 | 6.72 | 16.5 | 30.8 |
| SipHash-1-3 (std) | 6.19 | 6.87 | 7.82 | 8.67 | 10.8 | 15.4 | 23.4 | 39.5 | 72.5 | 137 |
| SipHash-2-4 | 6.74 | 6.96 | 8.66 | 10.1 | 13.7 | 21.2 | 35.4 | 66.1 | 124 | 239 |

**Note: A hashmap lookup takes about 1 ns on top of this, independent of the hashing algorithm.**

Hashers which do not pass SMHasher3:

| Hasher | 1 | 3 | 7 | 15 | 31 | 63 | 127 | 255 | 511 | 1023 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| foldhash (fast) | 0.77 | **0.76** | **0.64** | **0.63** | 1.41 | **1.85** | **2.91** | **5.49** | **10.3** | **18.9** |
| rustc-hash (FxHash 2) | 1.08 | 0.98 | 0.71 | 0.78 | 1.30 | 2.06 | 3.67 | 6.42 | 14.0 | 30.4 |
| rapidhash (fast) | 0.84 | 0.85 | 0.64 | 0.81 | **1.29** | 2.54 | 3.56 | 5.84 | 15.3 | 30.4 |
| fxhash (original FxHash) | 0.91 | 1.45 | 1.70 | 2.34 | 3.07 | 4.82 | 8.57 | 19.1 | 47.4 | 111 |
| fnv | **0.62** | 1.13 | 2.08 | 4.35 | 11.3 | 29.3 | 77.8 | 179 | 386 | 793 |
| xxh3 (xxhash-rust) | 7.79 | 11.5 | 11.5 | 11.3 | 12.3 | 12.3 | 13.2 | 20.9 | 28.6 | 33.3 |
| seahash | 13.6 | 13.3 | 13.3 | 11.3 | 12.0 | 12.6 | 14.0 | 21.8 | 39.9 | 87.6 |

For long strings, the speed in gigabytes per second, where higher is better. This is what the chart shows. Hashers
which pass SMHasher3:

| Hasher | 1023 | 2K | 4K | 8K | 16K | 32K | 64K |
|---|---:|---:|---:|---:|---:|---:|---:|
| **aHash** (AES) | **98.8** | **97.1** | **87.9** | **83.8** | **82.2** | **81.4** | **80.9** |
| **aHash** (fallback) | 27.7 | 26.2 | 25.5 | 24.9 | 24.9 | 24.9 | 24.8 |
| foldhash (quality) | 51.7 | 57.3 | 59.3 | 61.1 | 61.2 | 62.1 | 61.4 |
| rapidhash (quality) | 33.3 | 28.4 | 26.9 | 26.0 | 25.5 | 25.3 | 25.2 |
| SipHash-1-3 (std) | 7.46 | 7.56 | 7.71 | 7.80 | 7.80 | 7.80 | 7.78 |
| SipHash-2-4 | 4.28 | 4.32 | 4.36 | 4.40 | 4.43 | 4.44 | 4.44 |

Hashers which do not pass SMHasher3:

| Hasher | 1023 | 2K | 4K | 8K | 16K | 32K | 64K |
|---|---:|---:|---:|---:|---:|---:|---:|
| xxh3 (xxhash-rust) | 30.7 | 43.4 | 55.0 | **63.0** | **67.5** | **70.7** | **72.3** |
| foldhash (fast) | **54.0** | **58.6** | **59.9** | 61.2 | 61.2 | 61.9 | 61.3 |
| rustc-hash (FxHash 2) | 33.7 | 29.5 | 27.9 | 27.3 | 27.0 | 26.8 | 26.8 |
| rapidhash (fast) | 33.6 | 29.0 | 26.9 | 26.1 | 25.5 | 25.3 | 25.2 |
| seahash | 11.7 | 11.2 | 11.0 | 10.8 | 10.8 | 10.8 | 10.8 |
| fxhash (original FxHash) | 9.19 | 8.57 | 8.28 | 8.15 | 8.09 | 8.07 | 8.06 |
| fnv | 1.29 | 1.27 | 1.26 | 1.26 | 1.26 | 1.26 | 1.26 |

### How this was measured

* On one core of an AMD Ryzen AI 9 465 (Zen 5, up to 5.1 GHz) under Linux, with rustc 1.102.0-nightly (2026-11-22)
  and `RUSTFLAGS="-C target-cpu=native"`. This CPU has AES and VAES. "aHash (fallback)" was compiled with
  `-C target-feature=-aes` in addition.
* AHash uses its specialized hashers for integers. The hashers which do something more with a nightly compiler
  (foldhash, rapidhash and rustc-hash) were compiled with their `nightly` feature.
* With [Criterion](https://github.com/criterion-rs/criterion.rs). The code is in [tests/compare.rs](tests/compare.rs),
  and [how to run it](#reproducing-these-results) is below.
* Every hasher is used the way a `HashMap` uses it: Through `BuildHasher::hash_one`, with the `BuildHasher` which its
  crate provides, and a reference to the value. (`hash_one` is what selects aHash's specialized hashers. Building a
  hasher and calling `finish` on it does not use them.) A string is hashed as a `&String`. Each time is for hashing
  the same value over and over, which is the best case: The CPU predicts every branch and can work on several hashes
  at once.
* The time of a lookup is from a hashmap of 1000 `u64` keys, which
  fits in the L1 cache. It is not given for each hasher, because what it shows is mostly not the hasher: The same
  hasher's lookups differed by up to 15% between builds of the benchmark which did not change it.
* Repeated runs of one build agree to within 2%. How the compiler fits a hasher into the surrounding program matters
  more than that, and differs from one program to the next. SipHash is affected most: In a program which uses it
  for nothing but `u64` keys, it takes half the time it does here.
* The other hashers are the most widely used ones. Several of them are still being developed, so their numbers will
  change. The versions measured were foldhash 0.2.0, rapidhash 4.5.1,
  rustc-hash 2.1.3, fxhash 0.2.1, fnv 1.0.7, xxhash-rust 0.8.21, siphasher 1.0.4 and seahash 4.1.0, with hashbrown 0.17.2
  and Criterion 0.8.2.
  SipHash-1-3 is `std::collections::hash_map::RandomState`.

### AES and fallback

With AES, aHash hashes a string of any length in less time than with the fallback: In about 70% of the time for up to
15 bytes, and in less than a third of it from 1023 bytes up. A `u64` takes the same time, because both use the same
specialized hasher for integers.

Without `-C target-cpu=native` the fallback's times are within 15% of the ones above.

## Quality

A hasher in a library hashes whatever its callers give it, and cannot know what that will look like. So aHash regards
passing SMHasher as the least that a hasher for general use should do. A hasher which fails has some kind of input for
which its output is measurably not random, and sooner or later somebody's keys are of that kind. Such a hasher can
still be the right choice in a program whose author knows the algorithm and knows what the keys look like. It is not
a sound default, and in this comparison the hashers which fail are kept apart from the ones which pass.

**AHash passes every test of [SMHasher3](https://gitlab.com/fwojcik/smhasher3)**, with AES, with the fallback, and
with the substitute which the fallback uses on targets without a 128 bit product. The tests are run with the `--extra`
option, which is how the results which SMHasher3 publishes are run. The full output is checked into the
[smhasher subdirectory](../smhasher).

What is tested is the crate itself, through [C bindings](../smhasher/ahash-cbindings).
[run_smhasher3.sh](../smhasher/run_smhasher3.sh) builds and runs all of it. (SMHasher3 also has a port of aHash to C++
of its own, which it publishes results for under the name "rust-ahash". **That is not the algorithm of this crate**.)

SMHasher3 is a set of statistical tests: It finds hash functions whose output is not evenly distributed. It does not
test DOS resistance, so passing it is necessary and not sufficient.

## DOS resistance

AHash provides DOS resistance by incorporating random keys into the hash, so that the hashes cannot be predicted
without knowing the keys. Where the keys come from depends on the feature flags:

* With `runtime-rng` (which is on by default) they come from the operating system, via the `getrandom` crate.
* Without it but with `compile-time-rng`, the `const-random` crate generates random numbers at compile time, which
  are embedded in the binary.
* With neither, aHash falls back on fixed constants combined with the numeric value of memory addresses.
  This is somewhat strong if ASLR is turned on (it is by default in Rust) but for some platforms this is not available.
  As a result this should not be relied on. So if your program cannot use `runtime-rng`, because it needs to run
  in an environment without an operating system, it is strongly recommended to enable `compile-time-rng`.

In all of these cases each map gets different keys.

AHash is designed so that an attacker who does not know the keys cannot construct inputs which collide, or learn the keys
from the outside. [The FAQ](../FAQ.md#how-does-ahash-prevent-dos-attacks) has the threat model: What the attacker is
assumed to be able to do, and what aHash is designed to prevent.

AHash is **not** a cryptographic hash, there is no proof of its resistance, and it has not been through formal peer
review. Weaknesses have been found in it and were fixed, which is possible because its algorithm is not a fixed
standard. So it is important to use an up to date version. If you need the most conservative choice, that is SipHash,
which is what the standard library uses.

## Other hashers

What each of the crates above provides. "Keyed" is whether the `BuildHasher` of the crate uses keys which are random by
default. A hasher which is not keyed gives the same hashes in every program, so anyone can work out a set of inputs
which collide in advance.

The last column is whether it passes the SMHasher3 test suite. For aHash, foldhash and rapidhash it is the result of
running the crate itself through SMHasher3, in the versions [measured here](#how-this-was-measured). For the others it
is according to [the results which SMHasher3
publishes](https://gitlab.com/fwojcik/smhasher3/-/blob/main/results/README.md) or to their authors.

| Crate | Keyed | What its authors say about DOS resistance | Passes SMHasher3 |
|---|---|---|---|
| **aHash** | yes | Designed for it. See [above](#dos-resistance) | yes. See [Quality](#quality) |
| foldhash (quality) | yes | See its documentation | yes |
| foldhash (fast) | yes | See its documentation | no |
| rapidhash (quality) | yes | See its documentation | yes |
| rapidhash (fast) | yes | See its documentation | no |
| rustc-hash | no | "non-collision-resistant"; made for the compiler, where "these attacks aren't a concern" | no |
| fxhash | no | "not designed to prevent any attacks" | no. See [FxHash](#fxhash) |
| fnv | no | "provides no protection against collision attacks" | no |
| xxhash-rust (xxh3) | no | No claim | no |
| seahash | no | "It is not secure, nor does it aim to be" | no |
| SipHash-1-3 (std) | yes | "selected to provide resistance against HashDoS attacks" | yes |
| siphasher (SipHash-2-4) | no. Keys can be supplied | Designed as a defense against hash flooding, with a secret key | yes |

# Why use aHash over X

## SipHash

For a hashmap: Because aHash is several times faster. For typical keys, strings of 5 to 32 bytes, a hash takes 8 to 9
times as long to compute with SipHash-1-3 as with aHash using AES, and 5 to 6 times as long as with its fallback.

SipHash is however useful in other contexts, such as for a HMAC, where aHash would be completely inappropriate.

*SipHash-2-4* is designed to provide DOS attack resistance, and has no presently known attacks
against this claim that doesn't involve learning bits of the key.

SipHash is also available in the "1-3" variant which is about twice as fast as the standard version for long input.
The SipHash authors don't recommend using this variation when DOS attacks are a concern, but there are still no known
practical DOS attacks against the algorithm. Rust has opted for the "1-3" version as the default in `std::collections::HashMap`,
because the speed trade off of "2-4" was not worth it.

SipHash has a fixed specification and has been studied far more than aHash. So if the cost of a successful attack is
high and the time spent hashing does not matter, SipHash is the safer choice.

## foldhash and rapidhash

These two are the closest alternatives to aHash. [hashbrown](https://github.com/rust-lang/hashbrown) uses foldhash as
its default hasher. Each comes in a *fast* and a *quality* variant, and the fast variants are the ones which their map
types use.

Both are built on the folded multiply: Two 64 bit values are multiplied, and the two halves of the 128 bit product are
combined. AHash's fallback is built on the same multiplication, so the three are similar in kind. They differ in how
much they do with it.

Foldhash's fast variant hashes a key of up to 16 bytes with a single folded multiply. This makes it faster than aHash
for short keys, and it is also not enough for the output to pass SMHasher3. The fast variants are not meant to pass:
They give up some of the quality of the output for speed. By [the standard above](#quality) that rules them out as a
hasher for general use. The *quality* variants add a second round, and pass.

AHash's fallback does more for each key than a single multiplication, because of what aHash commits to:

* Each algorithm it uses has to pass the full SMHasher3 suite. There is no variant which gives that up.
* It is designed to resist DOS attacks. [The threat model](../FAQ.md#threat-model) says what that means: It includes
  an attacker who can see the hashes of the values it sends and adapt to them.
  [The design principles](../FAQ.md#design-principles) describe what this requires of an algorithm.

In terms of speed, are faster than aHash for single integers and for strings of under 15 bytes. 
(Though this difference is likely small in comparison to the rest of the hashmap operations.)

With AES, aHash is significantly faster for longer strings. A string can be hashed at about 80 GB
per second, against 60 for foldhash and 25 for rapidhash.

## FxHash

There are two hashers by this name. The `fxhash` crate is the original algorithm, which was taken from Firefox. The
`rustc-hash` crate has since replaced it with a new design.

In terms of performance, both are faster than aHash for integers. The original is slower than aHash for strings of
7 bytes or more. The new one is faster than aHash's fallback for strings of every length. Against the AES algorithm it
is faster for strings of 7 and 15 bytes, about the same for others of up to 127 bytes, and slower beyond that: At 1023
bytes it takes three times as long.
So it might seem like using FxHash for hashmaps when the key is a primitive is a good idea. This is *not* the case.

When the original FxHash is operating on a 4 or 8 byte input such as a u32 or a u64, it reduces to multiplying the input by a fixed
constant. This is a bad hashing algorithm because it means that lower bits can never be influenced by any higher bit. In
the context of a hashmap where the low order bits are used to determine which bucket to put an item in, this isn't
any better than the identity function. Any keys that happen to end in the same bit pattern will all collide.
Some examples of where this is likely to occur are:

* Strings encoded in base64
* Null terminated strings (when working with C code)
* Integers that have the lower bits as zeros. (IE any multiple of small power of 2, which isn't a rare pattern in computer programs.)
  * For example when taking lengths of data or locations in data it is common for values to
have a multiple of 1024, if these were used as keys in a map they will collide and end up in the same bucket.

The new design rotates the product at the end, so that the bits which depend on the whole input are the ones which
choose the bucket. This avoids the worst of the above. It does not pass SMHasher3 and does not aim to: Its authors
describe it as "non-collision-resistant".

Like any non-keyed hash FxHash can be attacked. But FxHash is so prone to this that you may find yourself doing it accidentally.

For example, it is possible to [accidentally introduce quadratic behavior by reading from one map in iteration order and writing to another.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

Because it is error-prone, FxHash should never be used as a default. In specialized instances where the keys are understood
and cannot be chosen by an attacker.

## FnvHash

FnvHash is also a poor default. It only handles one byte at a time, so its performance really suffers with large inputs.
It is also non-keyed so it is still subject to DOS attacks and [accidentally quadratic behavior.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

## XXHash and SeaHash

Both are made for hashing large amounts of data, such as for a checksum, with output which is the same everywhere.
Used as a `Hasher` they are slow for short input: For strings of up to 31 bytes they take five to fourteen times as
long as aHash. With AES, aHash is faster than both at every length. Its fallback is faster than SeaHash at every length,
and than XXH3 up to 511 bytes.

Neither claims DOS resistance, and the Rust crates for them do not use random keys by default. Neither passes SMHasher3.

## MurmurHash, CityHash, MetroHash, FarmHash, and HighwayHash

Murmur, City, Metro, Farm and Highway are all related, and appear to directly replace one another.

They are targeted at a different usecase. They are intended to work in distributed systems where the hash is expected
to be the same over time and from one computer to the next, efficiently hashing large volumes of data.

This is quite different from the needs of a Hasher used in a hashmap. In a map the typical value is under 10 bytes. None
of these algorithms scale down to handle that small of data at a competitive time. What's more the restriction that they
provide consistent output prevents them from taking advantage of different hardware capabilities on different CPUs. It makes
sense for a hashmap to work differently on a phone than on a server, or in WASM.

Of these only HighwayHash passes SMHasher3, and only it is designed to resist attacks. For Murmur, City and Farm there are
[ways to construct any number of inputs which collide](https://orlp.net/blog/breaking-hash-functions/), in some cases
whatever the seed.

If you need to persist or transmit a hash of a file, then HighwayHash seems to be the preferred solution, as it
offers high throughput for large objects and is DOS resistant when it is given a secret key.

## wyHash

Similarly, wyHash is targeted at hashmaps. WyHash is quite fast, but is not DOS resistant as it is normally used.

There are fixed strings which when encountered cause the internal state to reset, [unless the secret values it uses
are random as well as the seed](https://liams.website/articles/seed-independent-collisions-on-wyhash-and-rapidhash).

[rapidhash](#foldhash-and-rapidhash) is its successor.

# Reproducing these results

From this directory:

```text
# Everything, with aHash using AES:
RUSTFLAGS="-C target-cpu=native" cargo +nightly bench --features nightly

# aHash's fallback:
RUSTFLAGS="-C target-cpu=native -C target-feature=-aes" cargo +nightly bench --features nightly -- aHash

# The tables above, and the chart:
python3 summarize.py --chart
```

Which hashers pass SMHasher3 is a list in `summarize.py`. For aHash it comes from running the tests, which takes
about 20 minutes for each of the three:

```text
cd ../smhasher
./run_smhasher3.sh aes
./run_smhasher3.sh fallback
./run_smhasher3.sh nofold
```
