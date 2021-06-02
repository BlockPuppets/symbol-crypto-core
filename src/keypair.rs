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

use std::fmt;
use std::fmt::Debug;

use anyhow::Result;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

use core::{
    BlockCipher, KEY_BYTES_SIZE, KEYPAIR_LENGTH, KeyPairSchema, PrivateKey, PublicKey, Signature,
};

#[cfg(feature = "nis1")]
pub type Nis1 = nis1_crypto::keypair::Keypair;

pub type Sym = sym_crypto::keypair::Keypair;

/// It represents an asymmetric private/public encryption key.
///
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub struct Keypair<Kp: KeyPairSchema>(pub Kp);

impl<Kp: KeyPairSchema> Keypair<Kp> {
    /// Generate a `Keypair` random.
    ///
    /// # Example
    ///
    /// ```
    /// use  symbol_crypto_core::{Keypair, Sym};
    /// #
    /// # fn main() {
    /// #
    /// let keypair = Keypair::<Sym>::random();
    /// # println!("{}", keypair);
    /// # }
    /// ```
    pub fn random() -> Self {
        Self(<Kp>::random())
    }

    /// Construct a `Keypair` from the bytes of a `PublicKey` and `PrivateKey`.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing the `PublicKey` and `PrivateKey` as bytes.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is a `Keypair` or whose error value
    /// is an describing the error that occurred.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kp = <Kp>::from_bytes(bytes)?;
        Ok(Self(kp))
    }

    /// Construct a `Keypair` from a hex encoded private key string.
    ///
    /// # Inputs
    ///
    /// * `hex`: an `S` representing the hex private key (String or &str).
    ///
    /// # Example
    ///
    /// ```
    /// use symbol_crypto_core::{Keypair, Sym};
    /// #
    /// # fn main() {
    /// #
    /// let private_key_hex: &str =
    /// "7D3E959EB0CD66CC1DB6E9C62CB81EC52747AB56FA740CF18AACB5003429AD2E";
    /// let keypair = Keypair::<Sym>::from_hex_private_key(private_key_hex);
    /// # assert!(keypair.is_ok());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an `Keypair` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    pub fn from_hex_private_key<S: AsRef<str>>(hex: S) -> Result<Self> {
        let kp = <Kp>::from_hex_private_key(hex)?;
        Ok(Self(kp))
    }

    /// Construct a `Keypair` `PrivateKey` type.
    ///
    /// # Inputs
    ///
    /// * `private_key`: representing the `PrivateKey` type.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::str::FromStr;
    /// use symbol_crypto_core::{Keypair, PrivateKey, Sym};
    /// #
    /// # fn main() {
    /// #
    /// let private_key_hex: &str = "7D3E959EB0CD66CC1DB6E9C62CB81EC52747AB56FA740CF18AACB5003429AD2E";
    /// let private_key = PrivateKey::from_str(private_key_hex).unwrap();
    /// let keypair = Keypair::<Sym>::from_private_key(private_key);
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Keypair`
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let kp = <Kp>::from_private_key(private_key);
        Self(kp)
    }

    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `KEY_BYTES_SIZE` of bytes is the `PrivateKey`, and the next
    /// `KEY_BYTES_SIZE` bytes is the `PublicKey`.
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..KEY_BYTES_SIZE].copy_from_slice(self.0.private_key().as_bytes());
        bytes[KEY_BYTES_SIZE..].copy_from_slice(self.0.public_key().as_bytes());
        bytes
    }

    /// Signs a data bytes with a `Keypair`.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` representing the data to sign.
    ///
    /// # Example
    ///
    /// ```
    /// use symbol_crypto_core::{Keypair, Sym};
    /// #
    /// # fn main() {
    /// #
    /// let keypair = Keypair::<Sym>::random();
    /// let data = b"8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9";
    ///
    /// let signature = keypair.sign(data.as_ref());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Signature` the signature hash.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.0.sign(data)
    }

    /// Verify a `Signature` on a data with this Keypair public key.
    ///
    /// # Inputs
    ///
    /// * `data`: an `&[u8]` the data to verify.
    ///
    /// * `signature`: an `Signature` the signature hash.
    ///
    /// # Returns
    ///
    /// Returns `Ok` if the `Signature` was a valid signature created by this `Keypair`
    ///
    pub fn verify(&self, data: &[u8], signature: Signature) -> Result<()> {
        self.0.verify(data, signature)
    }

    pub fn private_key(&self) -> PrivateKey {
        self.0.private_key()
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Encode a message text using the signer's `PrivateKey` of this Keypair and receiver's
    /// `PublicKey`.
    ///
    /// # Inputs
    ///
    /// * `receiver_pk`: The receiver's public key.
    ///
    /// * `msg`: Message to encrypt.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::str::FromStr;
    /// use symbol_crypto_core::{Keypair, Sym, PublicKey};
    ///
    /// # fn main() {
    /// #
    /// # let signer_kp = Keypair::<Sym>::random();
    /// # let receiver_pk = PublicKey::from_str("645C6BB6526E209ED33162472BF75F06172309DC72214AE07CE68EB5A6496B4E").unwrap();
    ///
    /// let message = b"Symbol is awesome from Rust!";
    ///
    /// let encrypt_text = signer_kp.encrypt_message(receiver_pk.as_fixed_bytes(), message).unwrap();
    /// # println!("{:?}", encrypt_text);
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an encrypt message `Vec<u8>` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    pub fn encrypt_message(
        &self,
        receiver_pk: &[u8; KEY_BYTES_SIZE],
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        <Kp>::Crypto::encrypt_message(self.private_key().as_fixed_bytes(), receiver_pk, msg)
    }

    /// Decrypt a message text using the receiver's the PrivateKey of this Keypair and signer's
    /// PublicKey.
    ///
    /// # Inputs
    ///
    /// * `signer_pk`: The signer's public key.
    ///
    /// * `enc_msg`: Message encrypted.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::str::FromStr;
    /// use symbol_crypto_core::{Keypair, Sym, PublicKey};
    ///
    /// # fn main() {
    /// #
    /// let receiver_kp = Keypair::<Sym>::from_hex_private_key("A22A4BBF126A2D7D7ECE823174DFD184C5DE0FDE4CB2075D30CFA409F7EF8908").unwrap();
    /// let signer_pk = PublicKey::from_str("3FD283D8543C12B81917C154CDF4EFD3D48E553E6D7BC77E29CB168138CED17D").unwrap();
    ///
    /// let encrypt_text_vec = [
    ///     125, 59, 126, 248, 124, 129, 157, 100, 111, 84, 49, 163, 111, 68, 22, 137, 75, 132, 135,
    ///     217, 251, 158, 115, 74, 226, 172, 200, 208, 33, 183, 110, 103, 107, 170, 52, 174, 192, 110,
    ///     164, 44, 77, 69, 203, 48, 43, 17, 206, 143, 154, 155, 231, 72, 28, 24, 20, 241, 234, 202,
    ///     184, 66,
    /// ];
    ///
    /// let decrypted_text = receiver_kp.decrypt_message( signer_pk.as_fixed_bytes(), &encrypt_text_vec).unwrap();
    /// # println!("{}", String::from_utf8(decrypted_text).unwrap());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an decrypted message `Vec<u8>` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    pub fn decrypt_message(
        &self,
        signer_pk: &[u8; KEY_BYTES_SIZE],
        enc_msg: &[u8],
    ) -> Result<Vec<u8>> {
        <Kp>::Crypto::decrypt_message(self.private_key().as_fixed_bytes(), signer_pk, enc_msg)
    }
}

impl<C: KeyPairSchema> fmt::Display for Keypair<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{public_key: {:x}}}", self.public_key())
    }
}

#[cfg(feature = "serde")]
impl<C: KeyPairSchema> Serialize for Keypair<C> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let bytes = &self.to_bytes()[..];
        SerdeBytes::new(bytes).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d, C: KeyPairSchema> Deserialize<'d> for Keypair<C> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Keypair::from_bytes(bytes.as_ref()).map_err(SerdeError::custom)
    }
}

impl<C: KeyPairSchema> AsRef<C> for Keypair<C> {
    fn as_ref(&self) -> &C {
        &self.0
    }
}
