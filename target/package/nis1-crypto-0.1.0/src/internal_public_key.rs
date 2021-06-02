// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ed25519 internal public keys.
//!
use std::fmt::Debug;

use anyhow::{anyhow, Result};
use sha3::{Digest, Keccak512};
use signature::Verifier;

use super::{internal_private_key::ExpandedPrivateKey, internal_signature::InternalSignature};
use crate::core::curve25519::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use crate::core::{PrivateKey, PublicKey, Signature, KEY_BYTES_SIZE};

#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct InternalPublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for InternalPublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "ExpandedPublicKey({:?}), {:?})", self.0, self.1)
    }
}

impl AsRef<[u8]> for InternalPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<PrivateKey> for InternalPublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(private_key: PrivateKey) -> InternalPublicKey {
        let mut h: Keccak512 = Keccak512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        let mut secret_key = private_key.to_fixed_bytes();
        secret_key.reverse();

        h.update(&secret_key);
        hash.copy_from_slice(h.finalize().as_slice());

        digest.copy_from_slice(&hash[..32]);

        InternalPublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
            &mut digest,
        )
    }
}

impl From<PublicKey> for InternalPublicKey {
    /// Derive this public key from its corresponding `PrivateKey`.
    fn from(public_key: PublicKey) -> InternalPublicKey {
        let compressed = CompressedEdwardsY(public_key.to_fixed_bytes());
        let point = compressed
            .decompress()
            .ok_or(anyhow!("PointDecompressionError"))
            .unwrap();

        InternalPublicKey(compressed, point)
    }
}

impl<'a> From<&'a ExpandedPrivateKey> for InternalPublicKey {
    /// Derive this public key from its corresponding `ExpandedPrivateKey`.
    fn from(expanded_secret_key: &ExpandedPrivateKey) -> InternalPublicKey {
        let mut bits: [u8; 32] = expanded_secret_key.key.to_bytes();

        InternalPublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
            &mut bits,
        )
    }
}

impl InternalPublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; KEY_BYTES_SIZE] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES_SIZE] {
        &(self.0).0
    }

    // #[inline]
    // pub fn from_bytes(bytes: &[u8]) -> Result<InternalPublicKey> {
    //     ensure!(bytes.len() == KEY_BYTES_SIZE, "BytesLengthError");
    //
    //     let mut bits: [u8; 32] = [0u8; 32];
    //     bits.copy_from_slice(&bytes[..32]);
    //
    //     let compressed = CompressedEdwardsY(bits);
    //     let point = compressed
    //         .decompress()
    //         .ok_or(anyhow!("PointDecompressionError"))?;
    //
    //     Ok(InternalPublicKey(compressed, point))
    // }

    /// Internal utility function for mangling the bits of a (formerly
    /// mathematically well-defined) "scalar" and multiplying it to produce a
    /// public key.
    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
        bits: &mut [u8; 32],
    ) -> InternalPublicKey {
        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let point = &Scalar::from_bits(*bits) * &constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();

        InternalPublicKey(compressed, point)
    }
}

impl Verifier<Signature> for InternalPublicKey {
    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let signature = InternalSignature::from_bytes(signature.as_bytes())
            .map_err(|_| core::ed25519::SignatureError::new())?;

        let R: EdwardsPoint;
        let k: Scalar;
        let minus_A: EdwardsPoint = -self.1;

        let mut h: Keccak512 = Keccak512::new();
        h.update(signature.R.as_bytes());
        h.update(self.as_bytes());

        h.update(&message);

        k = Scalar::from_hash(h);
        R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s);

        if R.compress() == signature.R {
            Ok(())
        } else {
            Err(core::ed25519::SignatureError::new())
        }
    }
}
