// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rand::RngCore;
use regex::Regex;

pub fn is_hex(input: &str) -> bool {
    if input == "" {
        return false;
    }

    let re = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    re.is_match(input)
}

/// Decodes a hex string into raw bytes.
///
pub fn hex_to_vec(data: &str) -> Vec<u8> {
    hex::decode(data)
        .map_err(|err| panic!("Failed to decode hex data {} : {}", data, err))
        .unwrap()
}

pub fn random_bytes<const COUNT: usize>() -> [u8; COUNT] {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; COUNT];
    rng.try_fill_bytes(&mut buf).unwrap();
    buf
}
