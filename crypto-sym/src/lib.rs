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

pub use cipher::*;
pub use keypair::*;

mod cipher;
mod hkdf_sha256;
pub mod keypair;
