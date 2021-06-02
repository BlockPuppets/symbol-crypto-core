// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate core_crypto as core;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

use anyhow::{bail, Result};

use crate::core::curve25519::scalar::Scalar;

pub use self::cipher::*;
pub use self::keypair::*;

mod cipher;
mod internal_private_key;
mod internal_public_key;
mod internal_signature;
mod keccak_256;
pub mod keypair;

#[inline(always)]
pub(crate) fn check_scalar(bytes: [u8; 32]) -> Result<Scalar> {
    // Since this is only used in signature deserialisation (i.e. upon
    // verification), we can do a "succeed fast" trick by checking that the most
    // significant 4 bits are unset.  If they are unset, we can succeed fast
    // because we are guaranteed that the scalar is fully reduced.  However, if
    // the 4th most significant bit is set, we must do the full reduction check,
    // as the order of the basepoint is roughly a 2^(252.5) bit number.
    //
    // This succeed-fast trick should succeed for roughly half of all scalars.
    if bytes[31] & 240 == 0 {
        return Ok(Scalar::from_bits(bytes));
    }

    match Scalar::from_canonical_bytes(bytes) {
        None => bail!("ScalarFormatError"),
        Some(x) => Ok(x),
    }
}
