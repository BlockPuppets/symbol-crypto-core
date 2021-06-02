// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::core::{H256, SharedSecret, KEY_BYTES_SIZE};
use sha3::{Keccak256, Digest};

pub(crate) fn keccak256(master: SharedSecret) -> H256 {
    let sk_hash = Keccak256::digest(master.as_bytes());

    let mut derive_key: H256 = H256::default();
    derive_key.assign_from_slice(&sk_hash.as_slice()[0..KEY_BYTES_SIZE]);
    derive_key
}
