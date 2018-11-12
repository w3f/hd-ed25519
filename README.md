
Hierachical key derivation on ed255190-dalek

Almost all hierachical key derivation schemes for ed25519 have
vulnerabilities due to the "bit clamping" used in ed25519.
Instead of hierachical key derivation on ed255190, we recommend
using either a curve of cofactor 1 like secp256k1 or else
a cofactor avoiding representation of Ed25519 like
[ristretto](https://ristretto.group/) instead.  That said..

[BIP32-Ed25519](https://cardanolaunch.com/assets/Ed25519_BIP.pdf)
avoids the clamping by deriving new keys using only 224 bit scalars.
There are straightforward full key recovery attack if one permits
long key derivation paths along with either clamping by an Ed25519
library or does addition mod another besides 8*l.  Addition
implementaitons are normally either mod l or mod 256.

In this crate, we implement addition mod 8*l of numbers congruent
to 0 mod 8 using the method indicated by Mike Hamburg in
https://moderncrypto.org/mail-archive/curves/2017/000869.html

We divide the secret scalars by the cofactor 8 as integers,
add them mod l, and multiply them by 8 again as integers. 
We observe that this will not yield scalars whose high bit set to 1,
and thus is not compatable with most Ed25519 libraries.  
It works with ed25519-dalek because the underlying implementation is
constant-time and set the high bit when creating expanded secrety keys.

An alternative appraopch is detailed in https://moderncrypto.org/mail-archive/curves/2017/000866.html and https://github.com/hdevalence/curve25519-dalek/commit/2ae0bdb6df26a74ef46d4332b635c9f6290126c7


