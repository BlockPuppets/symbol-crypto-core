// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::core::{H256, SharedSecret};

const HKDF_INFO: &[u8; 8] = b"catapult";

pub(crate) fn hkdf_sha256(master: SharedSecret) -> H256 {
    let h = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = H256::zero();
    h.expand(HKDF_INFO, &mut out.as_mut())
        .expect("unexpected error in rust hkdf_sha256");
    out
}
