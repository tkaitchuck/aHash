# aHash

aHash is a hashing algorithm that uses the [hardware AES instruction](https://en.wikipedia.org/wiki/AES_instruction_set) on X86 processors.
aHash provides a very high quality 64 bit hash useful for hashmaps an similar applications.
aHash is designed for performance and is *not cryptographically secure*.

Similar to Sip_hash it is a keyed hash, so two hashers initialized with different keys will produce completely different hashes that cannot be predicted without knowing the keys. This prevents DOS attackes where an attacker sends a large number of items that get used as keys in a hashmap and the hashes collide.

## Speed

aHash uses two rounds of AES encryption using the AES-NI instruction per 16 bytes of input. On an intel i5-6200u this is around as fast as a single multiplication instruction per long. This is obviously much faster than most standard approaches to hashing, and does a much better job of scrambling data than most non-secure hashes.

On an intel i5-6200u compiled with flags `-C opt-level=3 -C target-cpu=native -C codegen-units=1 -C llvm-args=-unroll-threshold=1000`:

| Input   | SipHash 3-1 time | FnvHash   |FxHash time| aHash time|
|----------------|-----------|-----------|-----------|-----------|
| u8             | 12.415 ns | 2.0967 ns | **1.1531 ns** | 1.4706 ns |
| u16            | 13.095 ns | 1.3030 ns | **1.1589 ns** | 1.4949 ns |
| u32            | 12.303 ns | 2.1232 ns | **1.1491 ns** | 1.4988 ns |
| u64            | 14.648 ns | 4.3945 ns | **1.1623 ns** | 1.4992 ns |
| u128           | 17.207 ns | 9.5498 ns | **1.4231 ns** | 1.7255 ns |
| 1 byte string  | 15.867 ns | 2.5458 ns | **2.9808 ns** | **2.9892 ns** |
| 3 byte string  | 16.540 ns | 3.6615 ns | 4.1974 ns | **3.5952 ns** |
| 4 byte string  | 15.378 ns | 4.1979 ns | **2.1764 ns** | 3.1970 ns |
| 7 byte string  | 19.353 ns | 6.1037 ns | 4.8818 ns | **4.1436 ns** |
| 8 byte string  | 17.827 ns | 5.5392 ns | 3.6468 ns | **3.2937 ns** |
| 15 byte string | 22.211 ns | 12.148 ns | 7.0670 ns | **4.9879 ns** |
| 16 byte string | 19.646 ns | 10.535 ns | **4.0134 ns** | 4.7397 ns |
| 24 byte string | 21.526 ns | 17.539 ns | **4.3693 ns** | 5.2282 ns |
| 68 byte string | 32.711 ns | 67.454 ns | 8.8002 ns | **6.4633 ns** |
| 132 byte string| 52.617 ns | 159.16 ns | 16.876 ns | **7.6355 ns** |

As you can see above aHash provides the similar (~5x) speeup over SipHash that FxHash provides.

Rust by default uses SipHash because faster hash functions such as FxHash are predictable and vulnerable to denial of service attacks.
aHash has both very strong scrambling (inherited from AES) as well as very high performance, but is architecture speffic.

Similar to FxHash it perfroms well when dealing with large inputs because aHash reads 16 bytes at a time. (This is how it is able to out perfrom FxHash with large strings)
It also provides the reasonabably good performance when dealing with unaligned input. (notice the big performance gaps between 3 vs 4, 7 vs 8 and 15 vs 16 above.)

## Security

aHash is designed to prevent keys from being guessable. This means:
- It is a high quality hash that produces results that look highly random.
- It obays the '[strict avalanche criterion](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion)': 
Each bit of input can has the potential to flip every bit of the output.
    - Additionally, whether or not it does so depends on every bit in the Key.

This prevents DOS attacks that attempt to produce hash collisions by knowing how the hash wroks.
It is however not recomended to assume this property can hold if the attaker is allowed to SEE the hashed value.
AES is desinged to prevent an attacker from learning the key being used even if they can see the encryped output and select the plain text that is used.
*However* this property holds when 10 rounds are used. aHash uses only 2 rounds, so it likely won't hold up to this sort of attack.
For DOS prevention, this should not be a problem, as an attacker trying to produce collisions in a hashmap does not get to see the hash values that are beeing used inside of the map.

### aHash is not cryptographically secure

aHash should not be used for situations where cryptographic security is needed for several reasons.

1. It has not been analyzed for vulnerabilities and may leak bits of the key in its output.
2. It only uses 2 rounds of AES as opposed to the standard of 10. This likely makes it possible to guess the key by observing a large number of hashes.
3. Like any cypher based hash, it will show certain statistical deviations from truely random output when comparing a (VERY) large number of hashes.

There are several efforts to build a secure hash function that uses AES-NI for acceleration, but this is not one of them.

## Compatibility

Currently aHash is pre 1.0. So new versions may change the algorithm slightly resulting in the new version producing different hashes than the old version even with the same keys.
Additionally aHash does not currently guarantee that it won't produce different hash values for the same data on different machines. 

## Supported CPUs

Hardware AES instructions are built into Intel processors built after 2010 and AMD processors after 2012.
It is also available on [many other CPUs](https://en.wikipedia.org/wiki/AES_instruction_set) should in eventually
be able to get aHash to work. However only X86 and X86-64 are the only supported architectures at the moment, as currently
they are the only architectures for which Rust provides an intrinsic.