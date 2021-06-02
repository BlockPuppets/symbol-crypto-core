// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use sha3::{Digest, Keccak512};

use crate::core::{PrivateKey, PublicKey, Signature};
use crate::core::curve25519::{constants, edwards::CompressedEdwardsY, scalar::Scalar};
use super::internal_signature::InternalSignature;

pub struct ExpandedPrivateKey {
    pub key: Scalar,
    pub(crate) nonce: [u8; 32],
}

impl<'a> From<&'a PrivateKey> for ExpandedPrivateKey {
    fn from(secret_key: &'a PrivateKey) -> ExpandedPrivateKey {
        let mut h: Keccak512 = Keccak512::default();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        let mut secret_key_bytes = secret_key.to_fixed_bytes();
        secret_key_bytes.reverse();
        h.update(secret_key_bytes);

        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        ExpandedPrivateKey {
            key: Scalar::from_bits(lower),
            nonce: upper,
        }
    }
}

impl ExpandedPrivateKey {
    /// Sign a message with this `ExpandedKey`.
    ///
    #[allow(non_snake_case)]
    pub fn sign(&self, message: &[u8], public_key: PublicKey) -> Signature {
        let mut h: Keccak512 = Keccak512::new();
        let R: CompressedEdwardsY;
        let r: Scalar;
        let s: Scalar;
        let k: Scalar;

        h.update(&self.nonce);
        h.update(&message);
        r = Scalar::from_hash(h);

        R = (&r * &constants::ED25519_BASEPOINT_TABLE).compress();

        h = Keccak512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        h.update(&message);

        k = Scalar::from_hash(h);

        s = &(&k * &self.key) + &r;

        InternalSignature { R, s }.into()
    }
}
