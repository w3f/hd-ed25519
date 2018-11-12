//! Access fields of the `ExpandedSecretKey` type.  Ideally
//! [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) 
//! might expose these fields directly, but this might tempt missuse.
//!
//! All code here is copied form ed25519-dalek and therefore copyright
//! Isis Agora Lovecruft.  

use clear_on_drop::clear::Clear;
use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::edwards::{CompressedEdwardsY,EdwardsPoint},
use ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH;

#[repr(C)]
#[derive(Default)] // we derive Default in order to use the clear() method in Drop
pub struct ExpandedSecretKey {
    pub key: Scalar,
    pub nonce: [u8; 32],
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.key.clear();
        self.nonce.clear();
    }
}

impl ExpandedSecretKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; EXPANDED_SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];

        bytes[..32].copy_from_slice(self.key.as_bytes());
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8; EXPANDED_SECRET_KEY_LENGTH]) -> ExpandedSecretKey {
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[00..32]);
        upper.copy_from_slice(&bytes[32..64]);

        ExpandedSecretKey{
			key: Scalar::from_bits(lower),
			nonce: upper  
		}
    }
}
