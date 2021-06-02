// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// The length Symbol Aes IV in bytes.
pub const SYM_AES_IV_LENGTH: usize = 12;

/// The length Nis1 Aes IV in bytes.
pub const NIS_AES_IV_LENGTH: usize = 16;

/// The length Nis1 Salt in bytes.
pub const NIS_SALT_LENGTH: usize = 32;

/// The length Symbol Aes Tag in bytes.
pub const AES_TAG_LENGTH: usize = 16;

/// The length of an key in bytes.
pub const KEY_BYTES_SIZE: usize = 32;

/// The length of an key in str.
pub const KEY_STR_SIZE: usize = 64;

/// The length of an `Signature` in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of an `Keypair` in bytes.
pub const KEYPAIR_LENGTH: usize = KEY_BYTES_SIZE + KEY_BYTES_SIZE;
