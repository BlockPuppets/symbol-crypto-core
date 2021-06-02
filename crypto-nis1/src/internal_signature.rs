// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::{bail, ensure, Result};

use super::check_scalar;
use crate::core::curve25519::{edwards::CompressedEdwardsY, scalar::Scalar};
use crate::core::{Signature, SIGNATURE_LENGTH};

#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(non_snake_case)]
pub(crate) struct InternalSignature {
    /// `R` is an `EdwardsPoint`, formed by using an hash function with
    /// 512-bits output to produce the digest of:
    ///
    /// - the nonce half of the `ExpandedSecretKey`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.  The scalar is then multiplied by the distinguished
    /// basepoint to produce `R`, and `EdwardsPoint`.
    pub(crate) R: CompressedEdwardsY,

    /// `s` is a `Scalar`, formed by using an hash function with 512-bits output
    /// to produce the digest of:
    ///
    /// - the `r` portion of this `Signature`,
    /// - the `PublicKey` which should be used to verify this `Signature`, and
    /// - the message to be signed.
    ///
    /// This digest is then interpreted as a `Scalar` and reduced into an
    /// element in ℤ/lℤ.
    pub(crate) s: Scalar,
}

impl InternalSignature {
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    /// Construct a `Signature` from a slice of bytes.
    ///
    /// # Scalar Malleability Checking
    ///
    /// As originally specified in the ed25519 paper (cf. the "Malleability"
    /// section of the README in this repo), no checks whatsoever were performed
    /// for signature malleability.
    ///
    /// Later, a semi-functional, hacky check was added to most libraries to
    /// "ensure" that the scalar portion, `s`, of the signature was reduced `mod
    /// \ell`, the order of the basepoint:
    ///
    /// ```ignore
    /// if signature.s[31] & 224 != 0 {
    ///     return Err();
    /// }
    /// ```
    ///
    /// This bit-twiddling ensures that the most significant three bits of the
    /// scalar are not set:
    ///
    /// ```python,ignore
    /// >>> 0b00010000 & 224
    /// 0
    /// >>> 0b00100000 & 224
    /// 32
    /// >>> 0b01000000 & 224
    /// 64
    /// >>> 0b10000000 & 224
    /// 128
    /// ```
    ///
    /// However, this check is hacky and insufficient to check that the scalar is
    /// fully reduced `mod \ell = 2^252 + 27742317777372353535851937790883648493` as
    /// it leaves us with a guanteed bound of 253 bits.  This means that there are
    /// `2^253 - 2^252 + 2774231777737235353585193779088364849311` remaining scalars
    /// which could cause malleabilllity.
    ///
    /// RFC8032 [states](https://tools.ietf.org/html/rfc8032#section-5.1.7):
    ///
    /// > To verify a signature on a message M using public key A, [...]
    /// > first split the signature into two 32-octet halves.  Decode the first
    /// > half as a point R, and the second half as an integer S, in the range
    /// > 0 <= s < L.  Decode the public key A as point A'.  If any of the
    /// > decodings fail (including S being out of range), the signature is
    /// > invalid.
    ///
    /// However, by the time this was standardised, most libraries in use were
    /// only checking the most significant three bits.  (See also the
    /// documentation for `PublicKey.verify_strict`.)
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<InternalSignature> {
        ensure!(bytes.len() == SIGNATURE_LENGTH, "BytesLengthError");

        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        let s: Scalar;

        match check_scalar(upper) {
            Ok(x) => s = x,
            Err(x) => bail!(x),
        }

        Ok(InternalSignature {
            R: CompressedEdwardsY(lower),
            s,
        })
    }
}

// impl TryFrom<Signature> for InternalSignature {
//     type Error = SignatureError;
//
//     fn try_from(sig: Signature) -> Result<InternalSignature> {
//         InternalSignature::from_bytes(sig.as_bytes())
//     }
// }

impl From<InternalSignature> for Signature {
    fn from(sig: InternalSignature) -> Signature {
        Signature::from_slice(&sig.to_bytes())
    }
}
