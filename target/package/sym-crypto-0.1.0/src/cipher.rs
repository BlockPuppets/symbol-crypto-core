// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    AeadInPlace, Aes256Gcm, Tag,
};
use anyhow::{anyhow, ensure, Result};
use sha2::Sha512;

use super::hkdf_sha256::hkdf_sha256;

use crate::core::{
    derive_shared_secret, random_bytes, AesKey, BlockCipher, PrivateKey, PublicKey, AES_TAG_LENGTH,
    H256, KEY_BYTES_SIZE, SYM_AES_IV_LENGTH,
};

pub struct CryptoSym;

impl BlockCipher for CryptoSym {
    /// Encode a message text with AES-GCM algorithm using the signer's the PrivateKey and receiver's PublicKey.
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
        let iv = random_bytes::<SYM_AES_IV_LENGTH>();

        let signer_sk = PrivateKey::from(signer_sk);
        let receiver_pk = PublicKey::from(receiver_pk);

        let derive_key = derive_shared_key(signer_sk, receiver_pk);

        let (encrypted, auth_tag) = encrypt(iv, derive_key, msg)?;

        let mut enc = vec![];
        enc.extend_from_slice(&auth_tag);
        enc.extend_from_slice(&iv);
        enc.extend_from_slice(&encrypted);
        Ok(enc)
    }

    /// Decrypt a message text with AES-GCM algorithm using the receiver's the PrivateKey and signer's PublicKey.
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

        let iv = &enc_msg[AES_TAG_LENGTH..AES_TAG_LENGTH + SYM_AES_IV_LENGTH];
        let mut iv_bytes = [0u8; SYM_AES_IV_LENGTH];
        iv_bytes.copy_from_slice(&iv[..]);

        let tag = &enc_msg[0..AES_TAG_LENGTH];

        let mut msg_and_tag_bytes = Vec::with_capacity(enc_msg.len() - SYM_AES_IV_LENGTH);
        msg_and_tag_bytes.extend_from_slice(&enc_msg[AES_TAG_LENGTH + SYM_AES_IV_LENGTH..]);
        msg_and_tag_bytes.extend_from_slice(&tag[..]);

        let recipient_sk = PrivateKey::from(receiver_sk);
        let signer_pk = PublicKey::from(signer_pk);

        let enc_key = derive_shared_key(recipient_sk, signer_pk);

        let decrypt_vec = decrypt(iv_bytes, enc_key, &msg_and_tag_bytes)?;

        Ok(decrypt_vec)
    }
}

// internal functions.
fn derive_shared_key(secret_key: PrivateKey, public_key: PublicKey) -> H256 {
    let shared_secret = derive_shared_secret::<Sha512>(secret_key, public_key);
    hkdf_sha256(shared_secret)
}

/// Encrypt the given plaintext slice with AES-GCM algorithm with a 256-bit key and 96-bit nonce.
///
/// # Returns
///
/// A `Result` whose okay value is a ciphertext as a vector of bytes and auth_tag or whose error
/// value
/// is an `Error` describing the error that occurred.
fn encrypt(iv: [u8; SYM_AES_IV_LENGTH], derive_key: AesKey, msg: &[u8]) -> Result<(Vec<u8>, Tag)> {
    let key = GenericArray::from_slice(derive_key.as_fixed_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(&iv); // 96-bits; unique per message

    let mut msg_buf: Vec<u8> = vec![];
    msg_buf.extend_from_slice(msg);

    let auth_tag = cipher
        .encrypt_in_place_detached(nonce, &vec![], &mut msg_buf)
        .map_err(|e| anyhow!("{}", e))?;

    Ok((msg_buf, auth_tag))
}

/// Decrypt the given ciphertext slice with AES-GCM with a 256-bit key and 96-bit nonce.
///
/// # Returns
///
/// A `Result` whose okay value is a plaintext as a vector of bytes or whose error value
/// is an `Error` describing the error that occurred.
fn decrypt(iv: [u8; SYM_AES_IV_LENGTH], derive_key: AesKey, enc_msg: &[u8]) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(derive_key.as_fixed_bytes());
    let cipher = Aes256Gcm::new(key);

    let iv = GenericArray::from_slice(&iv);

    let decrypted = cipher.decrypt(iv, enc_msg).map_err(|e| anyhow!("{}", e))?;

    Ok(decrypted)
}
