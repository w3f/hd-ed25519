//! Hierarchical key derivation on curve25519 and less insane than BIP32
//!
//! 
//! 

use digest::Digest;
use generic_array::typenum::U64;

use curve25519_dalek::{
	constants,
	edwards::{CompressedEdwardsY,EdwardsPoint},
	scalar::Scalar
};
use ed25519_dalek::{PublicKey,ExpandedSecretKey};

use self::dup;


/// Generate an `ExpandedSecretKey` key directly from another
/// `ExpandedSecretKey` and extra secret data.
/// 
/// Anyone who requires a 32 byte `SecretKey` should generate
/// one manually using either `ed25519_dalek::SecretKey::generate`
/// or else by applying `ed25519_dalek::SecretKey::from_bytes` to
/// hash fucntion output with 256 bits of entropy.  
///
/// If a secure `ExpandedSecretKey` is provided then this operates
/// analogously to the "hard" code path in BIP32 when i >= 2^31.
/// In particular, both require the source private key to prove any
/// relationship between a source public key and any derivative keys
/// produced by this function, or between two derivative keys.
/// 
/// We deem the chain code from BIP32 supurfluous here because
/// `ExpandedSecretKey::nonce` carries sufficent information. 
/// We replace the 32 bit integer paramater in BIP32 with an iterator
/// of byte slices, which simpifies user code.  
/// We remove the silly scalar addion and nonce addition modulo 256
/// from BIP32-Ed25519's hard code path because simply replacing
/// the key and nonce suffice in this code path of BIP32 and
/// works better with .
///
pub fn generate_expanded_secret_key<'a,D,I>(
	esk: ExpandedSecretKey,
	context: &[u8], 
	entropy: I
) -> ExpandedSecretKey
where D: Digest<OutputSize = U64>, 
      I: IntoIterator<Item=&'a [u8]>
{
    let mut h: D = D::new();
    h.input(& esk.to_bytes();
    h.input(context);
	for e in entropy { h.input(e); }
    let r = h.result();

    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    lower.copy_from_slice(& r.as_slice()[00..32]);
    upper.copy_from_slice(& r.as_slice()[32..64]);

    lower[0]  &= 248;
    lower[31] &=  63;
    lower[31] |=  64;

    let esk = dup::ExpandedSecretKey{  // Ugly lack of fields hack
		key: Scalar::from_bits(lower), 
		nonce: upper, 
	}
	ExpandedSecretKey::from_bytes(esk.to_bytes()).unwrap()  // Ugly lack of fields hack
}


// Length in bytes of the chain codes we produce
//
// In fact, only 16 bytes sounds safe, but this never appears on chain,
// so no downsides to using 32 bytes.
pub const CHAIN_CODE_LENGTH : usize = 32;  

pub struct ExtendedKey<K> {
	pub key: K,

	// Chain codes are randomness 
	pub chaincode: [u8; CHAIN_CODE_LENGTH],
}

/// Extract the lowest 224 bits of entropy that keep the low three bits zero.
///
/// In principle, we take only 28 bytes for 224 bits, and then multiply by 
/// the cofactor 8, but it's easier to take 29, and then zero the low and
/// high bits leaving 224 bits.
fn shifted_scalar_of_224_bits(bytes: &[u8]) -> Scalar {
        debug_assert!(bytes.len() == 28);
    let mut lower: [u8; 32] = [0u8; 32];
        lower.copy_from_slice(& r.as_slice()[0..29]);  
    lower[0]  &= 248;
    lower[29] &= 7;
        Scalar::from_bits(lower);
}

///
pub fn remaining_derivations(esk: &ExpandedSecretKey) -> u32 {
        let key = dup::ExpandedSecretKey::from_bytes(esk.to_bytes).key.to_bytes();
        key[31] |= 128;  // Set normally cleared high bit
        key[29..32].iter().map(|i| i.count_zeros()).sum()
}

/// Key pair using an `ExpandedSecretKey` instead of `SecretKey` to permit key derivation.
#[repr(C)]
pub struct ExpandedKeypair {
    /// The secret half of this keypair.
    pub secret: ExpandedSecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl ExtendedKey<ExpandedKeypair> {
	/// Derive an expanded secret key
	///
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
	pub fn derive_secret_key<D>(&self, entropy: I) -> Option<ExtendedKey<ExpandedSecretKey>>
	where D: Digest<OutputSize = U64>,
          I: IntoIterator<Item=&'a [u8]>
	{
		let esk = self.key.secret.to_bytes();  // Ugly lack of fields hack 

	    let mut h: D = D::new();
	    h.input(self.key.public.as_bytes());
		h.input(&self.chaincode.1);
		for e in entropy { h.input(e); }
		let h1 = h.clone();
	    let r = h.result();

	    let mut chaincode: [u8; 32] = [0u8; CHAIN_CODE_LENGTH];
		chaincode.copy_from_slice(& r.as_slice()[32..32+CHAIN_CODE_LENGTH]);		

	    h1.input(& esk);  // We compute the nonce from the private key instead of the public key.
	    let r1 = h1.result();

		let mut esk = dup::ExpandedSecretKey::from_bytes(esk);  // Ugly lack of fields hack
		esk.nonce.copy_from_slice(& r1.as_slice()[32..64]);
		esk.key += shifted_scalar_of_224_bits(& r.as_slice()[0..29]);

        Some(ExtendedKey {
			key: ExpandedSecretKey::from_bytes(esk.to_bytes()).unwrap(),  // Ugly lack of fields hack
        	chaincode,
        })
	}

	/// Derive an expanded key pair
	pub fn derive_keypair<D>(&self, entropy: I) -> Option<ExtendedKey<ExpandedKeypair>>
	where D: Digest<OutputSize = U64>,
          I: IntoIterator<Item=&'a [u8]>
	{
		let ExtendedKey { key, chaincode } = self.derive_secret_key(entropy) ?;
        let esk = dup::ExpandedSecretKey::from_bytes(key.to_bytes());  // Ugly lack of fields hack
        let pk = (&esk.key * &constants::ED25519_BASEPOINT_TABLE).compress().to_bytes();
		Some(ExtendedKey {
			key: ExpandedKeypair { 
				secret: key, 
				public: PublicKey::from_bytes(pk) 
			},
			chaincode
		})
    }
}

impl ExtendedKey<ExpandedSecretKey> {
	pub fn derive_secret_key<D>(&self, entropy: I) -> Option<ExtendedKey<ExpandedSecretKey>>
	where D: Digest<OutputSize = U64>,
          I: IntoIterator<Item=&'a [u8]>
	{
		;
	}
}

impl ExtendedKey<PublicKey> {
	/// Derivative public key
	///
	/// We replace the 32 bit integer paramater in BIP32 with a free
	/// form byte array, which simpifies user code dramatically. 
	/// Anyone who knows the source secret key and the same byte array can
	/// can derive the matching public key, even if they lack the private key.
	///
	/// We produce a chain code that can be incorporated into subsequence
	/// key derivations' mask byte array, and is similarly known by seret
	/// key holders.
	pub fn derive_public_key<D>(pk: &PublicKey, mask: &[u8])
	  -> Result<(PublicKey, [u8; CHAIN_CODE_LENGTH]), ed25519_dalek::SignatureError>
	where D: Digest<OutputSize = U64>
	{
	    // Very ugly little hack to report the same errors at ed25519-dalek
		let pk0: EdwardsPoint = match CompressedEdwardsY(pk.to_bytes()).decompress().ok_or_else(|| {
			let dumb_sig = Signature::from_bytes([0u8; SIGNATURE_LENGTH]);
			pk.verify(b"", &dumb_sig).err().unwrap()
		}) ?;

	    let mut h: D = D::new();
	    h.input(&[2]);
	    h.input(pk.as_bytes());
	    h.input(mask);
	    let r = h.result();

	    let mut chaincode: [u8; 32] = [0u8; CHAIN_CODE_LENGTH];
		chaincode.copy_from_slice(& r.as_slice()[32..32+CHAIN_CODE_LENGTH]);		

	    pk += &shifted_scalar_of_224_bits(& r.as_slice()[0..29])
	          * &constants::ED25519_BASEPOINT_TABLE;
	    Ok((PublicKey::from_bytes(pk.compress().to_bytes()), chaincode))  // Ugly lack of fields hack
	}
}





#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 5);
    }
}
