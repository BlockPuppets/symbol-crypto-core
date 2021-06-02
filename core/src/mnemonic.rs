// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::str::FromStr;

use anyhow::Result;
use bip39::{Language, Mnemonic};

use super::PrivateKey;

/// Re-construct a `PrivateKey` from the supplied mnemonic and password.
///
pub fn from_mnemonic(mnemonic: &str, password: &str) -> Result<PrivateKey> {
    let mnemonic = Mnemonic::from_str(mnemonic)?;
    generate_with_mnemonic(mnemonic, password)
}

/// Construct a `PrivateKey` and Mnemonic rand from the supplied password.
///
pub fn create_with_mnemonic(password: &str) -> Result<(PrivateKey, String)> {
    let mnemonic = Mnemonic::generate_in(Language::English, 24)?;
    let secret_key = generate_with_mnemonic(mnemonic.clone(), password)?;
    Ok((secret_key, mnemonic.to_string()))
}

fn generate_with_mnemonic(mnemonic: Mnemonic, password: &str) -> Result<PrivateKey> {
    let mut seed: PrivateKey = PrivateKey::default();
    seed.assign_from_slice(
        &(mnemonic.to_seed(password).to_vec())[..std::mem::size_of::<PrivateKey>()],
    );

    Ok(seed)
}
