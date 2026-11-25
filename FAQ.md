## How does aHash prevent DOS attacks

AHash is designed to [prevent an adversary that does not know the key from being able to create hash collisions or partial collisions.](https://github.com/tkaitchuck/aHash/wiki/How-aHash-is-resists-DOS-attacks)

If you are a cryptographer and would like to help review aHash's algorithm, please reach out. 

The details of the algorithm are subject to change. What does not change is what it is designed to resist, and the
properties it is built to have.

### Threat model

The attacker is assumed to:

* Know everything except the keys: The source code of aHash, how the program was compiled, and what CPU it runs on.
* Be able to choose the values which are used as keys in a map: Any number of them, of any length and content.
* Be able to see the 64 bit hash of each of those values, and to choose the next values accordingly.
* Not be able to see any of the computation inside the hasher, or any value in the memory of the program.

Against such an attacker, aHash is designed so that:

* No inputs can be prepared in advance which can force collisions with much greater frequency than random chance, 
  whether in the full hash or in the bits which a map uses to choose a bucket. This includes inputs which collide 
  for only a fraction of all keys, if that fraction is much larger than chance.
* Forcing a full collision takes an attacker who adapts to what they see so much work that it gives them no practical 
  leverage over a conventional denial of service attack, which simply sends a lot of traffic.
* The cost of forcing a partial collision, in N bits of the hash, is exponential in N.
* Nothing which is learned about one map helps against another beyond what is assumed to be known, because each map has its own keys.

This does not cover:

* Other properties such as being able to distinguish the hash output from random bits.
* An attacker who knows, or controls the keys. Either because they can read the memory of the process, 
  or because the keys are not random: See the [flags](https://github.com/tkaitchuck/aHash/blob/master/README.md#flags) for where the keys come from.
* Any use other than in a hashmap. AHash is [not a cryptographic hash](#why-isnt-ahash-cryptographically-secure).

There is no formal proof that aHash meets these goals, and it has not been through scientific review.

This model has become stricter over time. Attacks which earlier versions were not designed against have been reported.
Each time the requirement was added, and the algorithm was changed to meet it. If a new kind of attack is found the
same will happen. This is one of the reasons the algorithm is not fixed.

### Design principles

Each of these exist because there is a way in which hash functions have been or could be attacked.

* **Input is combined with something the attacker cannot see before anything else is done with it.** Input could be mixed
  first, but there is no point: Mixing which involves no secret can be undone by anyone who knows the algorithm. Some
  hashers, MurmurHash among them, rely on mixing each block of input by itself, and the
  [attack on them](https://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-dos-reloaded/) simply undid it.
  Once input has been combined with a key, or with state which depends on the keys, the attacker no longer knows what
  is being mixed, and cannot choose input which makes a particular change to the state.
* **Input is not reduced beforehand** No step combines pieces of the input with each other into something smaller
  before they meet a key or the state. Any such step has collisions, and with no secret involved it is trivial to find
  them. They would then be collisions of the whole hash, whatever the keys.
* **The change which one update makes cannot be canceled by the next.** This is how collisions are constructed, and
  then chained, in most attacks on hash functions. Two things prevent it:
  * Between consecutive updates the state is mixed. This spreads the earlier update over the whole of the state, in a
    way which depends on values the attacker cannot see. So they do not know what the next input would have to cancel.
  * An update is not simply xored into the state in one place. It has more than one effect, through separate channels.
    A later input can be chosen to cancel one effect of an earlier one, but in doing so it has an effect of its own
    somewhere else, which would have to be canceled in turn, and so on.
* **Every value is mixed thoroughly before it reaches the output.** Enough that each bit of it affects every bit of the
  hash. (With AES this takes at least three rounds.)
* **The output does not expose the state.** The state is larger than the output, and every bit of the output depends on
  all of it, through mixing which cannot be undone from the output alone.

Both of aHash's algorithms follow these principles. AES brings constraints of its own, because of how a round of it
spreads a change, so the algorithm which uses it has more restrictions than the fallback.

Together these give the properties which can be tested:

* aHash obeys the '[strict avalanche criterion](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion)':
  Each bit of the input changes each bit of the output half of the time, and so does each bit of the keys. Pairs of
  output bits change independently of each other.
* Inputs which differ in only a byte or two, or only in their length, never have the same hash.
* A difference in one block of input cannot be canceled by a difference in the block which follows it.
* It is deliberately difficult to 'chain' collisions. (This has been the major technique used to weaponize attacks on other hash functions)

The crate's tests check these. Several of them construct the differences which an attack would use, and check that
none of them work for any of the keys tried. The algorithms are also required to pass the SMHasher3 test suite.

More details are available on [the wiki](https://github.com/tkaitchuck/aHash/wiki/How-aHash-is-resists-DOS-attacks),
which also has the history of the weaknesses which were reported and how they were fixed.
(A walk through of the algorithm there may be of an earlier version. The source code is the reference.)

## Why not use a cryptographic hash in a hashmap.

Cryptographic hashes are designed to make is nearly impossible to find two items that collide when the attacker has full control
over the input. This has several implications:

* They are very difficult to construct, and have to go to a lot of effort to ensure that collisions are not possible.
* They have no notion of a 'key'. Rather, they are fully deterministic and provide exactly one hash for a given input.

For a HashMap the requirements are different.

* Speed is very important, especially for short inputs. Often the key for a HashMap is a single `u32` or similar, and to be effective
the bucket that it should be hashed to needs to be computed in just a few CPU cycles.
* A hashmap does not need to provide a hard and fast guarantee that no two inputs will ever collide. Hence, hashCodes are not 256bits 
but are just 64 or 32 bits in length. Often the first thing done with the hashcode is to truncate it further to compute which among a few buckets should be used for a key. 
  * Here collisions are expected, and a cheap to deal with provided there is no systematic way to generated huge numbers of values that all
go to the same bucket.
  * This also means that unlike a cryptographic hash partial collisions matter. It doesn't do a hashmap any good to produce a unique 256bit hash if
the lower 12 bits are all the same. This means that even a provably irreversible hash would not offer protection from a DOS attack in a hashmap
because an attacker can easily just brute force the bottom N bits.

From a cryptography point of view, a hashmap needs something closer to a block cypher.
Where the input can be quickly mixed in a way that cannot be reversed without knowing a key.

## Why isn't aHash cryptographically secure

It is not designed to be. 
Attempting to use aHash as a secure hash will likely fail to hold up for several reasons:

1. aHash relies on random keys which are assumed to not be observable by an attacker. For a cryptographic hash all inputs can be seen and controlled by the attacker.
2. aHash has not yet gone through peer review, which is a pre-requisite for security critical algorithms.
3. Because aHash uses reduced rounds of AES as opposed to the standard of 10. Things like the SQUARE attack apply to part of the internal state.
(These are mitigated by other means to prevent producing collections, but would be a problem in other contexts).
4. Like any cypher based hash, it will show certain statistical deviations from truly random output when comparing a (VERY) large number of hashes. 
(By definition cyphers have fewer collisions than truly random data.)

There are efforts to build a secure hash function that uses AES-NI for acceleration, but aHash is not one of them.

## How is aHash so fast

AHash uses a number of tricks. 

One trick is taking advantage of specialization. If aHash is compiled on nightly it will take advantage of a specialized hash implementation for integers.

Another is taking advantage of hardware instructions.
When it is available aHash uses AES rounds using the AES-NI instruction. AES-NI is very fast (on an intel i7-6700 it 
is as fast as a 64 bit multiplication.) and handles 16 bytes of input at a time, while being a very strong permutation.

This is obviously much faster than most standard approaches to hashing, and does a better job of scrambling data than most non-secure hashes.

On an AMD Ryzen AI 9 465, compiled with the flag `-C target-cpu=native`, the time to hash one value with `hash_one`:

| Input   | SipHash 1-3 time | FnvHash time|FxHash time| aHash time| aHash Fallback* |
|----------------|-----------|-----------|-----------|-----------|---------------|
| u64              | 7.15 ns | 1.54 ns | **0.28 ns** | 0.51 ns | 0.51 ns |
| 1 byte string    | 6.19 ns | **0.62 ns** | 0.91 ns | 1.01 ns | 1.48 ns |
| 3 byte string    | 6.87 ns | 1.13 ns | 1.45 ns | **1.01 ns** | 1.49 ns |
| 7 byte string    | 7.82 ns | 2.08 ns | 1.70 ns | **1.01 ns** | 1.42 ns |
| 15 byte string   | 8.67 ns | 4.35 ns | 2.34 ns | **0.94 ns** | 1.35 ns |
| 31 byte string   | 10.8 ns | 11.3 ns | 3.07 ns | **1.22 ns** | 2.15 ns |
| 63 byte string   | 15.4 ns | 29.3 ns | 4.82 ns | **1.93 ns** | 3.07 ns |
| 127 byte string  | 23.4 ns | 77.8 ns | 8.57 ns | **3.43 ns** | 5.04 ns |
| 255 byte string  | 39.5 ns | 179 ns | 19.1 ns | **3.78 ns** | 9.17 ns |
| 511 byte string  | 72.5 ns | 386 ns | 47.4 ns | **6.11 ns** | 17.8 ns |
| 1023 byte string | 137 ns | 793 ns | 111 ns | **10.4 ns** | 36.9 ns |

* Fallback refers to the algorithm aHash would use if AES instructions are unavailable.
FxHash is the original algorithm, as in the `fxhash` crate. These numbers and those for more hashers are from
[the comparison](https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md), which describes how they were measured.

As you can see above aHash like `FxHash` provides a large speedup over `SipHash-1-3` which is already nearly twice as fast as `SipHash-2-4`.

Rust's HashMap by default uses `SipHash-1-3` because faster hash functions such as `FxHash` are predictable and vulnerable to denial of
service attacks. While `aHash` has both very strong scrambling and very high performance.

AHash performs well when dealing with large inputs because aHash reads 16 bytes at a time, and for long input works on
several blocks in parallel.

Because of this, and its optimized logic, `aHash` is able to outperform `FxHash` with strings of more than a few bytes.
It also provides especially good performance dealing with unaligned input.

### Which CPUs can use the hardware acceleration

Hardware AES instructions are built into Intel processors built after 2010 and AMD processors after 2012.
They are also available on [many other CPUs](https://en.wikipedia.org/wiki/AES_instruction_set), including most 64-bit ARM processors.

AHash can use them on x86, x86-64 and AArch64. It can also use them on 32-bit ARM, which needs a nightly compiler and the `nightly-arm-aes` feature.

They have to be enabled when the program is compiled: aHash does not detect the CPU when the program runs. Most targets do not
enable them by default. (`aarch64-apple-darwin` is one which does.) Elsewhere compile with `-C target-cpu=native` or `-C target-feature=+aes`,
or the fallback is used.

On x86-64 aHash also uses the 256 bit version of the AES instructions (VAES) for long input, if the CPU has them and they are enabled in
the same way.
