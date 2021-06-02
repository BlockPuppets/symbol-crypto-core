// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A Rust implementation of Nis1 and Symbol ed25519 keypair generation, signing, and verification.
//!
//! This is the reference documentation for the proptest API.
//!
//! For documentation on how to get started with Nis1 keypair and general usage
//! advice, please refer to the [Key pair](https://docs.nem.io/en/nem-sdk/private-key#6-2-create-key-pairs).
//!
//! For documentation on how to get started with Symbol keypair and general usage
//! advice, please refer to the [Key pair](https://docs.symbolplatform.com/concepts/cryptography.html#keypair).
//!

use std::fmt::Debug;

use anyhow::Result;

use super::{BlockCipher, PrivateKey, PublicKey, Signature, KEYPAIR_LENGTH, KEY_BYTES_SIZE};

/// This trait defines a schema: an association of symbol or nis1 keypair type.
///
pub trait KeyPairSchema: Sized + PartialEq + Debug + Copy {
    type Crypto: BlockCipher;

    /// Create a new `Keypair` with cryptographically random content.
    ///
    fn random() -> Self;

    /// Construct a `Keypair` from the bytes of a `PublicKey` and `PrivateKey`.
    ///
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Construct a `Keypair` from a hex encoded private key string.
    ///
    fn from_hex_private_key<S: AsRef<str>>(hex: S) -> Result<Self>;

    /// Construct a `Keypair` `PrivateKey` type.
    ///
    fn from_private_key(pk: PrivateKey) -> Self;

    fn private_key(&self) -> PrivateKey;

    fn public_key(&self) -> PublicKey;

    /// Signs a data bytes with a `Keypair`.
    ///
    fn sign(&self, data: &[u8]) -> Signature;

    /// Verify a `Signature` on a data with this Keypair public key.
    ///
    fn verify(&self, data: &[u8], signature: Signature) -> Result<()>;

    fn from_null_private_key(pk: PublicKey) -> Self;

    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `KEY_BYTES_SIZE` of bytes is the `PrivateKey`, and the next
    /// `KEY_BYTES_SIZE` bytes is the `PublicKey`.
    fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..KEY_BYTES_SIZE].copy_from_slice(self.private_key().as_bytes());
        bytes[KEY_BYTES_SIZE..].copy_from_slice(self.public_key().as_bytes());
        bytes
    }
}
