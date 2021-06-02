// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{KEY_BYTES_SIZE, KEYPAIR_LENGTH};

pub type AesKey = H256;
pub type SharedSecret = H256;

construct_fixed_hash! {
    /// 256 bit hash type.
    pub struct H256(KEY_BYTES_SIZE);
}

construct_fixed_hash! {
    /// 512 bit hash type.
    pub struct H512(KEYPAIR_LENGTH);
}
