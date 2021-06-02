// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A Rust implementation of Nem NIS1 ed25519 keypair generation, signing, and verification.
//!
//! This is the reference documentation for the proptest API.
//!
//! For documentation on how to get started with NIS1 keypair and general usage
//! advice, please refer to the [Key pair](https://docs.nem.io/en/nem-sdk/private-key#6-2-create-key-pairs).
//!
use std::fmt;
use std::str::FromStr;

use anyhow::{ensure, Result};
#[cfg(feature = "serde")]
use serde::{Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::Bytes as SerdeBytes;

use core::ed25519::Verifier;

use super::{internal_private_key::ExpandedPrivateKey, internal_public_key::InternalPublicKey};
use crate::cipher::CryptoNis1;
use crate::core::{is_hex, KeyPairSchema, PrivateKey, PublicKey, Signature, KEY_STR_SIZE};

/// It represents an Nis1 asymmetric private/public encryption key.
///
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub struct Keypair {
    /// The private half of this keypair.
    pub private_key: PrivateKey,
    /// The public half of this keypair.
    pub public_key: PublicKey,
}

impl KeyPairSchema for Keypair {
    type Crypto = CryptoNis1;

    /// Create a new Nis1 `Keypair` with cryptographically random content.
    ///
    fn random() -> Self {
        let private_key: PrivateKey = PrivateKey::random();
        let public_key: PublicKey = InternalPublicKey::from(private_key).to_bytes().into();

        Self {
            private_key,
            public_key,
        }
    }

    /// Construct a Nis1 `Keypair` from the bytes of a `PublicKey` and `PrivateKey`.
    ///
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kp = core::ed25519::Keypair::from_bytes(bytes)?;
        Ok(Self {
            private_key: kp.secret.to_bytes().into(),
            public_key: kp.public.to_bytes().into(),
        })
    }

    /// Construct a Nis1 `Keypair` from a hex encoded private key string.
    ///
    /// # Inputs
    ///
    /// * `hex`: an `S` representing the hex private key (String or &str).
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an Nis1 `Keypair` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    fn from_hex_private_key<S: AsRef<str>>(hex: S) -> Result<Self> {
        let hex = hex.as_ref();
        ensure!(is_hex(hex), "private_key it's not hex.");
        ensure!(
            KEY_STR_SIZE == hex.len(),
            format!("private key has unexpected size {}", hex.len())
        );

        let private_key: PrivateKey = PrivateKey::from_str(hex.as_ref())?;

        let public_key: PublicKey = (InternalPublicKey::from(private_key).to_bytes()).into();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Construct a Nis1 `Keypair` `PrivateKey` type.
    ///
    /// # Inputs
    ///
    /// * `private_key`: representing the `PrivateKey` type.
    ///
    /// # Returns
    ///
    /// A `Keypair`
    fn from_private_key(pk: PrivateKey) -> Self {
        let public_key: PublicKey = (InternalPublicKey::from(pk).to_bytes()).into();

        Self {
            private_key: pk,
            public_key,
        }
    }

    fn private_key(&self) -> PrivateKey {
        self.private_key
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Signs a data bytes with a Nis1 `Keypair`.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` representing the data to sign.
    ///
    /// # Returns
    ///
    /// A `Signature` the signature hash.
    fn sign(&self, data: &[u8]) -> Signature {
        let kp = *self;
        let expanded_sk: ExpandedPrivateKey = (&kp.private_key).into();
        expanded_sk.sign(data, kp.public_key)
    }

    /// Verify a `Signature` on a data with this Nis1 Keypair public key.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` the data to verify.
    ///
    /// * `signature`: an `Signature` the signature hash.
    ///
    /// # Returns
    ///
    /// Returns `Ok` if the `Signature` was a valid signature created by this Nis1 `Keypair`
    ///
    fn verify(&self, data: &[u8], signature: Signature) -> Result<()> {
        let pk = InternalPublicKey::from(self.public_key);
        Ok(pk.verify(data, &signature)?)
    }

    fn from_null_private_key(pk: PublicKey) -> Self {
        Self {
            private_key: PrivateKey::zero(),
            public_key: pk,
        }
    }
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " public_key: {:x}", self.public_key)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = &self.to_bytes()[..];
        SerdeBytes::new(bytes).serialize(serializer)
    }
}
