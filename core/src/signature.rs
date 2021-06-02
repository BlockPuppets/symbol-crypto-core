// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::SIGNATURE_LENGTH;

construct_fixed_hash! {
    /// 512 bit hash type.
    pub struct Signature(SIGNATURE_LENGTH);
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self::from_slice(bytes.into()))
    }
}
