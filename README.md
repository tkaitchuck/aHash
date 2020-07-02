# aHash

AHash is a high speed keyed hashing algorithm intended for use in in-memory hashmaps. It provides a high quality 64 bit hash.
AHash is designed for performance and is *not cryptographically secure*.

When it is available aHash takes advantage of the [hardware AES instruction](https://en.wikipedia.org/wiki/AES_instruction_set)
on X86 processors. If it is not available it falls back on a somewhat slower (but still DOS resistant) [algorithm based on
multiplication](https://github.com/tkaitchuck/aHash/wiki/AHash-fallback-algorithm).

AHash is a keyed hash, so two instances initialized with different keys will produce completely different hashes and the 
resulting hashes cannot be predicted without knowing the keys. This prevents DOS attacks where an attacker sends a large
number of items whose hashes collide that get used as keys in a hashmap.

# Goals

AHash is the fastest DOS resistant hash for use in HashMaps available in the Rust language.
Failing in any of these criteria will be treated as a bug.

# Non-Goals
AHash is not:

* A cryptographically secure hash
* Intended to be a MAC
* Intended for network or persisted use

It is not intended that different computers using aHash will arrive at the same hashe for the same input.
Similarly the same computer running different versions of aHash may hash the same input to different values. 
By not requiring consistency aHash is able to tailor the algorithm and take advantage of specialized hardware 
instructions for higher performance.

## Hash quality

**Both aHash's aes variant and the fallback pass the full [SMHasher test suite](https://github.com/rurban/smhasher)** (the output of the tests is checked into the smhasher subdirectory. 

At ~50GB/s aHash is the fastest algorithm to pass the full test suite by nearly a factor of 2. Even the fallback algorithm is in the top 5 in terms of throughput.

## Speed

When it is available aHash uses two rounds of AES encryption using the AES-NI instruction per 16 bytes of input.
On an intel i7-6700 this is as fast as a 64 bit multiplication, but it has the advantages of being a much stronger
permutation and handles 16 bytes at a time. This is obviously much faster than most standard approaches to hashing,
and does a better job of scrambling data than most non-secure hashes.

On an intel i7-6700 compiled on nightly Rust with flags `-C opt-level=3 -C target-cpu=native -C codegen-units=1`:

| Input   | SipHash 1-3 time | FnvHash time|FxHash time| aHash time| aHash Fallback* |
|----------------|-----------|-----------|-----------|-----------|---------------|
| u8             | 9.3271 ns | 0.808 ns  | **0.594 ns**  | 0.7704 ns | 0.781 ns |
| u16            | 9.5139 ns | 0.803 ns  | **0.594 ns**  | 0.7653 ns | 0.784 ns |
| u32            | 9.1196 ns | 1.4424 ns | **0.594 ns**  | 0.7637 ns | 0.784 ns |
| u64            | 10.854 ns | 3.0484 ns | **0.628 ns**  | 0.7788 ns | 0.800 ns |
| u128           | 12.465 ns | 7.0728 ns | 0.799 ns  | **0.6174 ns** | 0.6337 ns |
| 1 byte string  | 11.745 ns | 2.4743 ns | 2.4000 ns | **1.4904 ns** | 2.7111 ns |
| 3 byte string  | 12.066 ns | 3.5221 ns | 2.9253 ns | **1.4819 ns** | 2.4416 ns |
| 4 byte string  | 11.634 ns | 4.0770 ns | 1.8818 ns | **1.5244 ns** | 2.1690 ns |
| 7 byte string  | 14.762 ns | 5.9780 ns | 3.2282 ns | **1.5250 ns** | 2.1706 ns |
| 8 byte string  | 13.442 ns | 4.0535 ns | 2.9422 ns | **1.7141 ns** | 2.1694 ns |
| 15 byte string | 16.880 ns | 8.3434 ns | 4.6070 ns | **1.7150 ns** | 2.4403 ns |
| 16 byte string | 15.155 ns | 7.5796 ns | 3.2619 ns | **1.7191 ns** | 2.4394 ns |
| 24 byte string | 16.521 ns | 12.492 ns | 3.5424 ns | **1.6325 ns** | 2.7110 ns |
| 68 byte string | 24.598 ns | 50.715 ns | 5.8312 ns | 5.5012 ns | **4.8805 ns** |
| 132 byte string| 39.224 ns | 119.96 ns | 11.777 ns | **7.3218 ns** | 7.3331 ns |
|1024 byte string| 254.00 ns | 1087.3 ns | 156.41 ns | **27.305 ns** | 42.383 ns |

* Fallback refers to the algorithm aHash would use if AES instructions are unavailable.
For reference a hash that does nothing (not even reads the input data takes) **0.520 ns**. So that represents the fastest
possible time.

As you can see above aHash like `FxHash` provides a large speedup over `SipHash-1-3` which is already nearly twice as fast as `SipHash-2-4`.

Rust's HashMap by default uses `SipHash-1-3` because faster hash functions such as `FxHash` are predictable and vulnerable to denial of
service attacks. While `aHash` has both very strong scrambling as well as very high performance.

AHash performs well when dealing with large inputs because aHash reads 8 or 16 bytes at a time. (depending on availability of AES-NI)

Because of this, and it's optimized logic, `aHash` is able to outperform `FxHash` with strings.
It also provides especially good performance dealing with unaligned input.
(Notice the big performance gaps between 3 vs 4, 7 vs 8 and 15 vs 16 in `FxHash` above)

For more a more representative performance comparison which includes the overhead of using a HashMap, see [HashBrown's benchmarks](https://github.com/rust-lang/hashbrown#performance) as HashBrown now uses aHash as it's hasher by default.

## Security

AHash is designed to [prevent an adversary that does not know the key from being able to create hash collisions or partial collisions.](https://github.com/tkaitchuck/aHash/wiki/Attacking-aHash-or-why-it's-good-enough-for-a-hashmap)

This achieved by ensuring that:

* aHash is designed to resist differential crypto analysis. Meaning it should not be possible to devise a scheme to "cancel" out a modification of the internal state from a block of input via some corresponding change in a subsequent block of input.
  * This is achieved by not performing any "premixing" - This reversible mixing gave previous hashes such as murmurhash confidence in their quality, but could be undone by a deliberate attack.
  * Before it is used each chunk of input is "masked" such as by xoring it with an unpredictable value.
* aHash obeys the '[strict avalanche criterion](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion)':
Each bit of input has the potential to flip every bit of the output.
* Similarly each bit in the key can affect every bit in the output.
* Input bits never affect just one or a very few bits in intermediate state. This is specifically designed to prevent [differential attacks aimed to cancel previous input](https://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-dos-reloaded/)
* The `finish` call at the end of the hash is designed to not expose individual bits of the internal state. 
  * For example in the main algorithm 256bits of state and 256bits of keys are reduced to 64 total bits using 3 rounds of AES encryption. Reversing this is more than non-trivial as most of the information is by definition gone, and any given bit of the internal state is fully diffused across the output.
* In both aHash and the fallback the internal state is divided into two halves which are updated by two unrelated techniques using the same input. - This means that if there is a way to attack one of them it likely won't be able to attack both of them at the same time.
* It is deliberately difficult to 'chain' collisions.
  * To attack  Previous attacks on hash functions have relied on the the ability


### aHash is not cryptographically secure

AHash should not be used for situations where cryptographic security is needed.
It is not intended for this and will likely fail to hold up for several reasons.

1. It has not yet been analyzed by any third party.
2. The input keys, and output results, are assumed to be largely non-observable. (Unlike cryptographic hashes where EVERYTHING is under the attacker's control)
3. It uses reduced rounds of AES as opposed to the standard of 10. This means that things like the SQUARE attack apply. (These are mitigated by other means to prevent producing collections, but would be a problem in other contexts).
4. Like any cypher based hash, it will show certain statistical deviations from truly random output when comparing a (VERY) large number of hashes. 

There are several efforts to build a secure hash function that uses AES-NI for acceleration, but aHash is not one of them.

## Compatibility

New versions of aHash may change the algorithm slightly resulting in the new version producing different hashes than
the old version even with the same keys. Additionally aHash does not guarantee that it won't produce different
hash values for the same data on different machines, or even on the same machine when recompiled.

For this reason aHash is not recommended for cases where hashes need to be persisted.

## Accelerated CPUs

Hardware AES instructions are built into Intel processors built after 2010 and AMD processors after 2012.
It is also available on [many other CPUs](https://en.wikipedia.org/wiki/AES_instruction_set) should in eventually
be able to get aHash to work. However only X86 and X86-64 are the only supported architectures at the moment, as currently
they are the only architectures for which Rust provides an intrinsic.

aHash also uses `sse2` and `sse3` instructions. X86 processors that have `aesni` also have these instruction sets.

## Why not cryptographic hash in a hashmap.

Cryptographic hashes are designed to make is nearly impossible to find two items that collide when the attacker has full control
over the input. This has several implications:

* They are very difficult to construct, and have to go to a lot of effort to ensure that collisions are not possible. 
* They have no notion of a 'key' rather they are fully deterministic and provide exactly one hash for a given input.

For a HashMap the requirements are different.

* Speed is very important, especially for short inputs. Often the key for a HashMap is a single `u32` or similar, and to be effective
the bucket that it should be hashed to needs to be computed in just a few CPu cycles.
* A hashmap does not need to provide a hard and fast guarantee that no two inputs will ever collide. Hence hashCodes are not 256bits 
but are just 64 or 32 bits in length. Often the first thing done with the hashcode is to truncate it further to compute which among a small number of buckets should be used for a key. 
  * Here collisions are expected and a cheap to deal with provided there is no systematic way to generated huge numbers of values that all
go to the same bucket.
  * This also means that unlike a cryptographic hash partial collisions matter. It doesn't do a hashmap any good to produce a unique 256bit hash if
the lower 12 bits are all the same. This means that even a provably irreversible hash would not offer protection from a DOS attack in a hashmap
because an attacker can easily just brute force the bottom N bits.

From a cryptography point of view, a hashmap needs something closer to a block cypher.
Where the input can be quickly mixed in a way that cannot be reversed without knowing a key.

# Why use aHash over X

## SipHash

For a hashmap: Because aHash is faster.

SipHash is however useful in other contexts, such as for a HMAC, where aHash would be completely inappropriate.

*SipHash-2-4* is designed to provide DOS attack resistance, and has no presently known attacks
against this claim that doesn't involve learning bits of the key.

SipHash is also available in the "1-3" variant which is about twice as fast as the standard version.
The SipHash authors don't recommend using this variation when DOS attacks are a concern, but there are still no known
practical DOS attacks against the algorithm. Rust has opted for the "1-3" version as the  default in `std::collections::HashMap`,
because the speed trade off of "2-4" was not worth it.

As you can see in the table above, aHash is **much** faster than even *SipHash-1-3*, but it also provides DOS resistance,
and any attack against the accelerated form would likely involve a weakness in AES.

## FxHash

In terms of performance, aHash is faster than the FXhash for strings and byte arrays but not primitives.
So it might seem like using Fxhash for hashmaps when the key is a primitive is a good idea. This is *not* the case.

When FX hash is operating on a 4 or 8 bite input such as a u32 or a u64, it reduces to multiplying the input by a fixed
constant. This is a bad hashing algorithm because it means that lower bits can never be influenced by any higher bit. In
the context of a hashmap where the low order bits are being used to determine which bucket to put an item in, this isn't
any better than the identity function. Any keys that happen to end in the same bit pattern will all collide. Some examples of where this is likely to occur are:

* Strings encoded in base64
* Null terminated strings (when working with C code)
* Integers that have the lower bits as zeros. (IE any multiple of small power of 2, which isn't a rare pattern in computer programs.)  
  * For example when taking lengths of data or locations in data it is common for values to
have a multiple of 1024, if these were used as keys in a map they will collide and end up in the same bucket.

Like any non-keyed hash FxHash can be attacked. But FxHash is so prone to this that you may find yourself doing it accidentally.

For example it is possible to [accidentally introduce quadratic behavior by reading from one map in iteration order and writing to another.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

Fxhash flaws make sense when you understand it for what it is. It is a quick and dirty hash, nothing more.
it was not published and promoted by its creator, it was **found**!

Because it is error-prone, FxHash should never be used as a default. In specialized instances where the keys are understood
it makes sense, but given that aHash is faster on almost any object, it's probably not worth it.

## FnvHash

FnvHash is also a poor default. It only handles one byte at a time, so it's performance really suffers with large inputs.
It is also non-keyed so it is still subject to DOS attacks and [accidentally quadratic behavior.](https://accidentallyquadratic.tumblr.com/post/153545455987/rust-hash-iteration-reinsertion)

## MurmurHash, CityHash, MetroHash, FarmHash, HighwayHash, XXHash, SeaHash

Murmur, City, Metro, Farm and Highway are all related, and appear to directly replace one another. Sea and XX are independent
and compete.

They are all fine hashing algorithms, they do a good job of scrambling data, but they are all targeted at a different
usecase. They are intended to work in distributed systems where the hash is expected to be the same over time and from one
computer to the next, efficiently hashing large volumes of data.

This is quite different from the needs of a Hasher used in a hashmap. In a map the typical value is under 10 bytes. None
of these algorithms scale down to handle that small of data at a competitive time. What's more the restriction that they
provide consistent output prevents them from taking advantage of different hardware capabilities on different CPUs. It makes
since for a hashmap to work differently on a phone than on a server, or in wasm.

If you need to persist or transmit a hash of a file, then using one of these is probably a good idea. HighwayHash seems to be the preferred solution du jour. But inside a simple Hashmap, stick with aHash.

## AquaHash

AquaHash is structured similarly to aHash. (Though the two were designed completely independently). AquaHash does not scale down nearly as well and
does poorly with for example a single `i32` as input. It's only implementation at this point is in C++.

## t1ha

T1ha is fast at large sizes and the output is of high quality, but it is not clear what usecase it aims for.
It has many different versions and is very complex, and uses hardware tricks, so one might infer it is meant for
hashmaps like aHash. But any hash using it take at least **20ns**, and it doesn't outperform even SipHash until the
input sizes are larger than 128 bytes. So uses are likely niche.

# License

Licensed under either of:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.


