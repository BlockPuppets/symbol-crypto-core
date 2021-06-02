// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use aes::Aes256;
use anyhow::{ensure, Result};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha3::Keccak512;

use crate::core::{
    derive_shared_secret, random_bytes, BlockCipher, PrivateKey, PublicKey, H256, KEY_BYTES_SIZE,
    NIS_AES_IV_LENGTH, NIS_SALT_LENGTH,
};
use super::keccak_256::keccak256;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct CryptoNis1;

impl BlockCipher for CryptoNis1 {
    /// Encode a message text with AES algorithm using the signer's the PrivateKey and receiver's PublicKey.
    ///
    /// # Inputs
    ///
    /// * `signer_sk`: The signer's private key.
    ///
    /// * `receiver_pk`: The receiver's public key.
    ///
    /// * `msg`: Message to encrypt.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an encrypt message `Vec<u8>` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    fn encrypt_message(
        signer_sk: &[u8; KEY_BYTES_SIZE],
        receiver_pk: &[u8; KEY_BYTES_SIZE],
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        let iv = random_bytes::<NIS_AES_IV_LENGTH>();
        let salt = random_bytes::<NIS_SALT_LENGTH>();
        let signer_sk: PrivateKey = signer_sk.into();
        let receiver_pk: PublicKey = receiver_pk.into();

        let derive_key = derive_shared_key(salt, signer_sk, receiver_pk);

        let encrypted = encrypt(iv, derive_key, msg)?;
        let mut enc = vec![];
        enc.extend_from_slice(&salt);
        enc.extend_from_slice(&iv);
        enc.extend_from_slice(&encrypted);
        Ok(enc)
    }

    /// Decrypt a message text with AES algorithm using the receiver's the PrivateKey and signer's PublicKey.
    ///
    /// # Inputs
    ///
    /// * `receiver_sk`: The receiver's private key.
    ///
    /// * `signer_pk`: The signer's public key.
    ///
    /// * `enc_msg`: Message encrypted.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::str::FromStr;
    /// use symbol_crypto_core::{PrivateKey, PublicKey,decrypt_message };
    ///
    /// # fn main() {
    /// #
    /// let receiver_sk = PrivateKey::from_str("A22A4BBF126A2D7D7ECE823174DFD184C5DE0FDE4CB2075D30CFA409F7EF8908").unwrap();
    /// let signer_pk = PublicKey::from_str("3FD283D8543C12B81917C154CDF4EFD3D48E553E6D7BC77E29CB168138CED17D").unwrap();
    ///
    /// let encrypt_text_vec = [
    ///     125, 59, 126, 248, 124, 129, 157, 100, 111, 84, 49, 163, 111, 68, 22, 137, 75, 132, 135,
    ///     217, 251, 158, 115, 74, 226, 172, 200, 208, 33, 183, 110, 103, 107, 170, 52, 174, 192, 110,
    ///     164, 44, 77, 69, 203, 48, 43, 17, 206, 143, 154, 155, 231, 72, 28, 24, 20, 241, 234, 202,
    ///     184, 66,
    /// ];
    ///
    /// let decrypted_text = decrypt_message( receiver_sk.as_fixed_bytes(), signer_pk.as_fixed_bytes(), &encrypt_text_vec).unwrap();
    /// # println!("{}", String::from_utf8(decrypted_text).unwrap());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an decrypted message `Vec<u8>` or whose error value
    /// is an `failure::Error` describing the error that occurred.
    fn decrypt_message(
        receiver_sk: &[u8; KEY_BYTES_SIZE],
        signer_pk: &[u8; KEY_BYTES_SIZE],
        enc_msg: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(!enc_msg.is_empty(), "msg cannot be empty");

        let iv = &enc_msg[NIS_SALT_LENGTH..NIS_SALT_LENGTH + NIS_AES_IV_LENGTH];
        let mut iv_bytes = [0u8; NIS_AES_IV_LENGTH];
        iv_bytes.copy_from_slice(&iv[..]);

        let mut salt_bytes = [0u8; NIS_SALT_LENGTH];
        salt_bytes.clone_from_slice(&enc_msg[0..NIS_SALT_LENGTH]);

        let mut enc_msg_bytes =
            Vec::with_capacity(enc_msg.len() - (NIS_SALT_LENGTH + NIS_AES_IV_LENGTH));
        enc_msg_bytes.extend_from_slice(&enc_msg[NIS_SALT_LENGTH + NIS_AES_IV_LENGTH..]);

        let recipient_sk: PrivateKey = receiver_sk.into();
        let signer_pk: PublicKey = signer_pk.into();

        let enc_key = derive_shared_key(salt_bytes, recipient_sk, signer_pk);

        let decrypt_vec = decrypt(iv_bytes, enc_key, &enc_msg_bytes)?;

        Ok(decrypt_vec)
    }
}

// internal functions.
fn derive_shared_key(
    salt: [u8; NIS_SALT_LENGTH],
    mut secret_key: PrivateKey,
    public_key: PublicKey,
) -> H256 {
    secret_key.0.reverse();
    let mut shared_secret = derive_shared_secret::<Keccak512>(secret_key, public_key);
    let mut i = 0;
    while i < shared_secret.0.len() {
        shared_secret.0[i] ^= salt[i];
        i += 1;
    }
    keccak256(shared_secret)
}

/// Encrypt the given plaintext slice with AES algorithm with a 256-bit key and 16-bytes nonce.
///
/// # Returns
///
/// A `Result` whose okay value is a ciphertext as a vector of bytes and auth_tag or whose error
/// value
/// is an `Error` describing the error that occurred.
fn encrypt(iv: [u8; NIS_AES_IV_LENGTH], derive_key: H256, msg: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(derive_key.as_bytes(), &iv)?;
    let encrypt = cipher.encrypt_vec(&msg);

    Ok(encrypt)
}

/// Decrypt the given ciphertext slice with AES with a 256-bit key and 16-bytes nonce.
///
/// # Returns
///
/// A `Result` whose okay value is a plaintext as a vector of bytes or whose error value
/// is an `Error` describing the error that occurred.
fn decrypt(iv: [u8; NIS_AES_IV_LENGTH], derive_key: H256, enc_msg: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(&derive_key.as_bytes(), &iv)?;
    let decrypted = cipher.decrypt_vec(&enc_msg)?;

    Ok(decrypted)
}
