// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::Result;
use curve25519::edwards::CompressedEdwardsY;
use curve25519::scalar::Scalar;
use sha3::Digest;

use super::{PrivateKey, PublicKey, SharedSecret, H256, KEY_BYTES_SIZE};

/// This trait defines an association of symbol or nis1 encrypt and decrypt message.
///
pub trait BlockCipher: Sized {
    fn encrypt_message(
        signer_sk: &[u8; KEY_BYTES_SIZE],
        receiver_pk: &[u8; KEY_BYTES_SIZE],
        msg: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt_message(
        receiver_sk: &[u8; KEY_BYTES_SIZE],
        signer_pk: &[u8; KEY_BYTES_SIZE],
        enc_msg: &[u8],
    ) -> Result<Vec<u8>>;
}

// internal functions.
pub fn derive_shared_secret<D: Digest>(
    secret_key: PrivateKey,
    public_key: PublicKey,
) -> SharedSecret {
    let public = CompressedEdwardsY::from_slice(public_key.as_ref())
        .decompress()
        .unwrap();

    let secret = scalar_from_sk::<D>(secret_key);

    let shared_point = secret * &(public);
    let shared_point_compressed = shared_point.compress();
    SharedSecret::from(shared_point_compressed.as_bytes())
}

// internal functions.
fn scalar_from_sk<D: Digest>(secret_key: PrivateKey) -> Scalar {
    let sk_hash = D::digest(secret_key.as_bytes());

    let mut sk_hash_fix: H256 = H256::default();
    sk_hash_fix.assign_from_slice(&sk_hash.as_slice()[0..32]);

    sk_hash_fix.0[0] &= 0xF8; // The lowest three bits must be 0
    sk_hash_fix.0[31] &= 0x7F; // The highest bit must be 0
    sk_hash_fix.0[31] |= 0x40; // The second highest bit must be 1

    Scalar::from_bits(sk_hash_fix.into())
}
