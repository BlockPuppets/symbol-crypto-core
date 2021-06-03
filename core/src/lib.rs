// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub extern crate curve25519_dalek as curve25519;
pub extern crate ed25519_dalek as ed25519;
#[macro_use]
extern crate fixed_hash;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub use self::block_cipher::*;
pub use self::constants::*;
pub use self::hashes::*;
pub use self::keypair_schema::KeyPairSchema;
#[cfg(feature = "with_mnemonic")]
pub use self::mnemonic::*;
pub use self::private_key::*;
pub use self::public_key::*;
pub use self::signature::*;
pub use self::utils::*;
pub use self::keypair::*;

mod block_cipher;
mod constants;
mod hashes;
mod keypair_schema;
#[cfg(feature = "with_mnemonic")]
mod mnemonic;
mod private_key;
mod public_key;
mod signature;
mod utils;
mod keypair;
