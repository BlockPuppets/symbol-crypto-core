// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::Result;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};

use super::{block_cipher::BlockCipher, KEY_BYTES_SIZE};

#[cfg(feature = "with_mnemonic")]
use crate::mnemonic;

construct_fixed_hash! {
    /// 256 bit hash type.
    pub struct PrivateKey(KEY_BYTES_SIZE);
}

#[cfg(feature = "with_mnemonic")]
impl PrivateKey {
    /// Constructs a `PrivateKey` the supplied mnemonic and password
    ///
    pub fn from_mnemonic(mnemonic: &str, password: &str) -> Result<Self> {
        mnemonic::from_mnemonic(mnemonic, password)
    }

    /// Constructs a hash type from the given reference
    /// to the mutable bytes array of fixed length.
    ///
    pub fn create_with_mnemonic(password: &str) -> Result<(PrivateKey, String)> {
        mnemonic::create_with_mnemonic(password)
    }
}

impl PrivateKey {
    pub fn encrypt_message<C: BlockCipher>(
        &self,
        receiver_pk: &[u8; KEY_BYTES_SIZE],
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        C::encrypt_message(self.as_fixed_bytes(), receiver_pk, msg)
    }

    pub fn decrypt_message<C: BlockCipher>(
        &self,
        signer_pk: &[u8; KEY_BYTES_SIZE],
        enc_msg: &[u8],
    ) -> Result<Vec<u8>> {
        C::decrypt_message(self.as_fixed_bytes(), signer_pk, enc_msg)
    }
}

#[cfg(feature = "serde")]
impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_bytes();
        SerdeBytes::new(bytes).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Ok(PrivateKey::from_slice(bytes.as_ref()))
    }
}
