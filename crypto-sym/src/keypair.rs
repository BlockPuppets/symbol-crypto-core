// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A Rust implementation of Symbol ed25519 keypair generation, signing, and verification.
//!
//! This is the reference documentation for the proptest API.
//!
//! For documentation on how to get started with Symbol keypair and general usage
//! advice, please refer to the [Key pair](https://docs.symbolplatform.com/concepts/cryptography.html#keypair).
//!
use ::std::convert::TryInto;
use ::std::fmt;

use anyhow::{ensure, Result};
use rand::thread_rng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;

use core::ed25519::{self, Verifier};

use super::CryptoSym;
use crate::core::{
    hex_to_vec, is_hex, KeyPairSchema, PrivateKey, PublicKey, Signature, KEY_STR_SIZE,
};

/// It represents an Symbol asymmetric private/public encryption key.
///
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub struct Keypair {
    /// The private half of this keypair.
    pub private_key: PrivateKey,
    /// The public half of this keypair.
    pub public_key: PublicKey,
}

impl KeyPairSchema for Keypair {
    type Crypto = CryptoSym;

    /// Create a new Symbol `Keypair` with cryptographically random content.
    ///
    fn random() -> Self {
        let mut csprng = thread_rng();
        let sk = ed25519::SecretKey::generate(&mut csprng);
        let pk: ed25519::PublicKey = (&sk).into();

        Self {
            private_key: PrivateKey::from(sk.to_bytes()),
            public_key: PublicKey::from(pk.to_bytes()),
        }
    }

    /// Construct a Symbol `Keypair` from the bytes of a `PublicKey` and `PrivateKey`.
    ///
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kp = ed25519::Keypair::from_bytes(bytes)?;
        Ok(Keypair::from(PrivateKey::from(kp.secret.as_bytes())))
    }

    /// Construct a Symbol `Keypair` from a hex encoded private key string.
    ///
    /// # Inputs
    ///
    /// * `hex`: an `S` representing the hex private key (String or &str).
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an Symbol `Keypair` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    fn from_hex_private_key<S: AsRef<str>>(hex: S) -> Result<Self> {
        let hex = hex.as_ref();
        ensure!(is_hex(hex), "private_key it's not hex.");

        ensure!(
            KEY_STR_SIZE == hex.len(),
            format!("private key has unexpected size {}", hex.len())
        );

        let sk = ed25519::SecretKey::from_bytes(&hex_to_vec(hex))?;

        let pk: ed25519::PublicKey = (&sk).into();

        Ok(Self {
            private_key: PrivateKey::from(sk.to_bytes()),
            public_key: PublicKey::from(pk.to_bytes()),
        })
    }

    /// Construct a Symbol `Keypair` `PrivateKey` type.
    ///
    /// # Inputs
    ///
    /// * `private_key`: representing the `PrivateKey` type.
    ///
    /// # Returns
    ///
    /// A `Keypair`
    fn from_private_key(pk: PrivateKey) -> Self {
        let sk = ed25519::SecretKey::from_bytes(pk.as_bytes()).unwrap();

        let pk: ed25519::PublicKey = (&sk).into();

        Self {
            private_key: PrivateKey::from(sk.to_bytes()),
            public_key: PublicKey::from(pk.to_bytes()),
        }
    }

    fn private_key(&self) -> PrivateKey {
        self.private_key
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Signs a data bytes with a Symbol `Keypair`.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` representing the data to sign.
    ///
    /// # Returns
    ///
    /// A `Signature` the signature hash.
    fn sign(&self, data: &[u8]) -> Signature {
        let kp = ed25519::Keypair::from_bytes(&self.to_bytes()).unwrap();

        let expanded_sk: ed25519::ExpandedSecretKey = (&kp.secret).into();
        (expanded_sk.sign(data, &kp.public).to_bytes()).into()
    }

    /// Verify a `Signature` on a data with this Symbol Keypair public key.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` the data to verify.
    ///
    /// * `signature`: an `Signature` the signature hash.
    ///
    /// # Returns
    ///
    /// Returns `Ok` if the `Signature` was a valid signature created by this Symbol `Keypair`
    ///
    fn verify(&self, data: &[u8], signature: Signature) -> Result<()> {
        let pk = ed25519::PublicKey::from_bytes(self.public_key.as_bytes())?;
        let signature: ed25519::Signature = (signature.as_bytes()).try_into()?;
        Ok(pk.verify(data, &signature)?)
    }

    fn from_null_private_key(pk: PublicKey) -> Self {
        Self {
            private_key: PrivateKey::zero(),
            public_key: pk,
        }
    }
}

impl<'a> From<&'a PrivateKey> for Keypair {
    fn from(sk: &'a PrivateKey) -> Self {
        Self::from_hex_private_key(format!("{:x}", sk)).unwrap()
    }
}

impl From<PrivateKey> for Keypair {
    fn from(sk: PrivateKey) -> Self {
        Self::from_hex_private_key(format!("{:x}", sk)).unwrap()
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

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Keypair::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}