//! Hierarchical key derivation on curve25519 with cleaner structure than BIP32
//!
//! As in BIP32, we produce a chain code that can be incorporated into
//! subsequence key derivations, and is similarly known by seret
//! key holders.  We improve on BIP32 in several respects though:
//!
//! We replace the 32 bit integer paramater in BIP32 with a free form
//! byte array, optionally presented as a hash state.  We expect this
//! simpifies user code by avoiding any allocation requirements for
//! integer paramaters.
//!
//! We do not conflate the "soft" derivation path that supports public
//! key derivation with the "hard" derivation path that simply prodiuces
//! some new private key.

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate ed25519_dalek;

#[cfg(any(test))]
extern crate sha2;

use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
// TODO use clear_on_drop::clear::Clear;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::CompressedEdwardsY; // EdwardsPoint
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{ExpandedSecretKey, PublicKey};

mod dup;

/// Generate an `ExpandedSecretKey` key directly from another
/// `ExpandedSecretKey` and extra secret data.
///
/// Anyone who requires a 32 byte `SecretKey` should generate
/// one manually using either `ed25519_dalek::SecretKey::generate`
/// or else by applying `ed25519_dalek::SecretKey::from_bytes` to
/// hash fucntion output with 256 bits of entropy.
///
/// We recommend generating a `SecretKey` manually over using this
/// function, as both methods provide analogs of the "hard" code
/// path in BIP32 when i >= 2^31.  In particular, all three require
/// the source private key to prove any relationship between a source
/// public key and any derivative keys produced by this function, or
/// between two derivative keys.
///
/// We deem the chain code from BIP32 supurfluous here because
/// `ExpandedSecretKey::nonce` carries sufficent information.
/// We replace the 32 bit integer paramater in BIP32 with an iterator
/// of byte slices, which simpifies user code.  
/// We remove the silly scalar addion and nonce addition modulo 256
/// from BIP32-Ed25519's hard code path because simply replacing
/// the key and nonce suffice in this code path of BIP32.
pub fn expanded_secret_key_prehashed<'a, D, I>(
    esk: ExpandedSecretKey,
    mut h: D,
) -> ExpandedSecretKey
where
    D: Digest<OutputSize = U64>,
{
    h.input(&esk.to_bytes() as &[u8]);
    let r = h.result();

    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    lower.copy_from_slice(&r.as_slice()[00..32]);
    upper.copy_from_slice(&r.as_slice()[32..64]);

    lower[0] &= 248;
    lower[31] &= 63;
    lower[31] |= 64;

    let esk = dup::ExpandedSecretKey {
        // Ugly lack of fields hack
        key: Scalar::from_bits(lower),
        nonce: upper,
    };
    ExpandedSecretKey::from_bytes(&esk.to_bytes()).unwrap() // Ugly lack of fields hack
}

// Length in bytes of the chain codes we produce
//
// In fact, only 16 bytes sounds safe, but this never appears on chain,
// so no downsides to using 32 bytes.
pub const CHAIN_CODE_LENGTH: usize = 32;

/// Key pair using an `ExpandedSecretKey` instead of `SecretKey` to permit key derivation.
#[repr(C)]
pub struct ExpandedKeypair {
    /// The secret half of this keypair.
    pub secret: ExpandedSecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl ExpandedKeypair {
    pub fn sign_prehashed<D>(
        &self,
        h: D,
        context: Option<&'static [u8]>,
    ) -> ed25519_dalek::Signature
    where
        D: Digest<OutputSize = U64> + Default,
    {
        self.secret.sign_prehashed::<D>(h, &self.public, context)
    }
}

/*
impl From<ExpandedSecretKey> for ExpandedKeypair {
	fn from(secret: ExpandedSecretKey) -> ExpandedKeypair {
		let public = ExpandedSecretKey::from_bytes(&esk).unwrap().into();  // hack for secret.clone().into();
		ExpandedKeypair { secret, public }
	}
}
*/

pub struct ExtendedKey<K> {
    pub key: K,

    // Chain codes are randomness that 
    pub chaincode: [u8; CHAIN_CODE_LENGTH],
}

impl ExtendedKey<ExpandedKeypair> {
    /// Derive an expanded secret key
    ///
    /// We derive a full 255 bit scalar mod 8*l with zero low bits

    /// We employ the 224 bit scalar trick from [BIP32-Ed25519](https://cardanolaunch.com/assets/Ed25519_BIP.pdf)
    /// so that addition with normal Ed25519 scalars
    ///
    /// We replace the 32 bit integer paramater in BIP32 with a free
    /// form byte array, which simpifies user code dramatically.
    /// Anyone who knows the source public key and the same byte array can
    /// derive the matching secret key, even if they lack the private keys.
    ///
    /// We produce a chain code that can be incorporated into subsequence
    /// key derivations' mask byte array, and is similarly known by public
    /// key holders.
    ///
    /// We continue deriving the nonce as in `unrecognisably_derive_secret_key`
    /// above bec ause the nonce must always remain secret.
    pub fn derive_secret_key_prehashed<D>(&self, mut h: D) -> ExtendedKey<ExpandedSecretKey>
    where
        D: Digest<OutputSize = U64> + Clone,
    {
        let esk = self.key.secret.to_bytes(); // Ugly lack of fields hack

        h.input(self.key.public.as_bytes());
        h.input(&self.chaincode);
        let mut h_secret = h.clone();
        let r = h.result();

        let mut chaincode = [0u8; CHAIN_CODE_LENGTH];
        chaincode.copy_from_slice(&r.as_slice()[32..32 + CHAIN_CODE_LENGTH]);

        h_secret.input(&esk as &[u8]); // We compute the nonce from the private key instead of the public key.
        let r_secret = h_secret.result();

        let mut esk = dup::ExpandedSecretKey::from_bytes(&esk); // Ugly lack of fields hack
        esk.nonce.copy_from_slice(&r_secret.as_slice()[32..64]);

        let mut lower = [0u8; 32];
        lower.copy_from_slice(&r.as_slice()[0..32]);
        // lower[31] &= 0b00001111;
        lower[0] &= 248;
        lower[31] &= 64 + 63;
        divide_scalar_by_cofactor(&mut lower);
        let mut secret_scalar = esk.key.to_bytes();
        divide_scalar_by_cofactor(&mut secret_scalar);
        let ss = Scalar::from_bits(lower) + Scalar::from_bits(secret_scalar);
        secret_scalar.copy_from_slice(&ss.to_bytes());
        multiply_scalar_by_cofactor(&mut secret_scalar);
        esk.key = Scalar::from_bits(secret_scalar);

        ExtendedKey {
            key: ExpandedSecretKey::from_bytes(&esk.to_bytes()).unwrap(), // Ugly lack of fields hack
            chaincode,
        }
    }

    /// Derive an expanded key pair
    pub fn derive_keypair_prehashed<D>(&self, h: D) -> ExtendedKey<ExpandedKeypair>
    where
        D: Digest<OutputSize = U64> + Clone,
    {
        let ExtendedKey { key, chaincode } = self.derive_secret_key_prehashed(h);
        let esk = dup::ExpandedSecretKey::from_bytes(&key.to_bytes()); // Ugly lack of fields hack
        let pk = (&esk.key * &constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        ExtendedKey {
            key: ExpandedKeypair {
                secret: key,
                public: PublicKey::from_bytes(&pk).unwrap(),
            },
            chaincode,
        }
    }
}

impl ExtendedKey<ExpandedSecretKey> {
    pub fn derive_secret_key<D>(&self, h: D) -> ExtendedKey<ExpandedSecretKey>
    where
        D: Digest<OutputSize = U64> + Clone,
    {
        let esk = self.key.to_bytes();
        let secret = ExpandedSecretKey::from_bytes(&esk).unwrap(); // hack: self.key.clone();
        let public = ExpandedSecretKey::from_bytes(&esk).unwrap().into(); // hack: secret.clone().into();
        ExtendedKey {
            key: ExpandedKeypair { secret, public },
            chaincode: self.chaincode.clone(),
        }.derive_secret_key_prehashed(h)
    }
}

impl ExtendedKey<PublicKey> {
    /// Derivative public key
    ///
    /// Anyone who knows the source secret key, chain code, and byte array can
    /// can derive the matching secret key.  
    ///
    /// We derive a 32 but integer
    ///
    /// We replace the 32 bit integer paramater in BIP32 with a free
    /// form byte array, which simpifies user code dramatically.
    ///
    /// We produce a chain code that can be incorporated into subsequence
    /// key derivations' mask byte array, and is similarly known by seret
    /// key holders.
    pub fn derive_public_key_prehashed<D>(&self, mut h: D) -> ExtendedKey<PublicKey>
    where
        D: Digest<OutputSize = U64> + Clone,
    {
        h.input(self.key.as_bytes());
        h.input(&self.chaincode);
        let r = h.result();

        let mut chaincode = [0u8; CHAIN_CODE_LENGTH];
        chaincode.copy_from_slice(&r.as_slice()[32..32 + CHAIN_CODE_LENGTH]);

        let mut pk = CompressedEdwardsY::from_slice(self.key.as_bytes())
            .decompress()
            .unwrap();
        let mut lower = [0u8; 32];
        lower.copy_from_slice(&r.as_slice()[0..32]);
        // lower[31] &= 0b00001111;
        lower[0] &= 248;
        lower[31] &= 64 + 63;
        pk += &Scalar::from_bits(lower) * &constants::ED25519_BASEPOINT_TABLE;

        ExtendedKey {
            key: PublicKey::from_bytes(pk.compress().as_bytes()).unwrap(), // Ugly lack of fields hack
            chaincode,
        }
    }
}

fn divide_scalar_by_cofactor(scalar: &mut [u8; 32]) {
    let mut low = 0u8;
    for i in scalar.iter_mut().rev() {
        let r = *i & 0b00000111; // save remainder
        *i >>= 3; // divide by 8
        *i += low;
        low = r << 5;
    }
}

fn multiply_scalar_by_cofactor(scalar: &mut [u8; 32]) {
    let mut high = 0u8;
    for i in scalar.iter_mut() {
        let r = *i & 0b11100000; // carry bits
        *i <<= 3; // multiply by 8
        *i += high;
        high = r >> 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SecretKey;
    use rand::{thread_rng, Rng};
    use sha2::{Digest, Sha512};

    #[test]
    fn cofactor_adjustment() {
        let mut x: [u8; 32] = thread_rng().gen();
        x[31] &= 0b00011111;
        let mut y = x.clone();
        multiply_scalar_by_cofactor(&mut y);
        divide_scalar_by_cofactor(&mut y);
        assert_eq!(x, y);

        let mut x: [u8; 32] = thread_rng().gen();
        x[0] &= 0b11111000;
        let mut y = x.clone();
        divide_scalar_by_cofactor(&mut y);
        multiply_scalar_by_cofactor(&mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn public_vs_private_paths() {
        let mut rng = thread_rng();
        let chaincode = [0u8; CHAIN_CODE_LENGTH];
        let mut h: Sha512 = Sha512::default();
        h.input(b"Just some test message!");

        let secret_key = SecretKey::generate(&mut rng);
        let mut extended_expanded_keypair = ExtendedKey {
            key: ExpandedKeypair {
                secret: ExpandedSecretKey::from_secret_key::<Sha512>(&secret_key),
                public: PublicKey::from_secret::<Sha512>(&secret_key),
            },
            chaincode,
        };
        let mut extended_public_key = ExtendedKey {
            key: PublicKey::from_secret::<Sha512>(&secret_key),
            chaincode,
        };

        let context = Some(b"testing testing 1 2 3" as &[u8]);

        for i in 0..30 {
            let extended_expanded_keypair1 =
                extended_expanded_keypair.derive_keypair_prehashed(h.clone());
            let extended_public_key1 = extended_public_key.derive_public_key_prehashed(h.clone());
            assert_eq!(
                extended_expanded_keypair1.chaincode, extended_public_key1.chaincode,
                "Chain code derivation failed!"
            );
            assert_eq!(
                extended_expanded_keypair1.key.public, extended_public_key1.key,
                "Public and secret key derivation missmatch!"
            );
            extended_expanded_keypair = extended_expanded_keypair1;
            extended_public_key = extended_public_key1;
            h.input(b"Another");

            if i % 5 == 0 {
                let good_sig = extended_expanded_keypair.key
                    .sign_prehashed::<Sha512>(h.clone(), context);
                let h_bad = h.clone().chain(b"oops");
                let bad_sig = extended_expanded_keypair.key
                    .sign_prehashed::<Sha512>(h_bad.clone(), context);

                assert!(
                    extended_public_key.key
                        .verify_prehashed::<Sha512>(h.clone(), context, &good_sig)
                        .is_ok(),
                    "Verification of a valid signature failed!"
                );
                assert!(
                    extended_public_key.key
                        .verify_prehashed::<Sha512>(h.clone(), context, &bad_sig)
                        .is_err(),
                    "Verification of a signature on a different message passed!"
                );
                assert!(
                    extended_public_key.key
                        .verify_prehashed::<Sha512>(h_bad, context, &good_sig)
                        .is_err(),
                    "Verification of a signature on a different message passed!"
                );
            }
        }
    }
}
