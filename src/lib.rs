// Copyright 2021 BlockPuppets developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![deny(broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! # Complete Symbol & Nis1 blockchain crypto library implementation.
//!
//! ## Quickstart: `prelude`
//!
//! A prelude is provided which imports all the important data types and traits for you. Use this
//! when you want to quickly bootstrap a new project.
//!
//! ```no_run
//! # #[allow(unused)]
//! use symbol_crypto_core::prelude::*;
//! ```
//!
//! Examples on how you can use the types imported by the prelude can be found in
//! the [`examples` directory of the repository](https://github.com/BlockPuppets/symbol-crypto-core/tree/master/examples)
//! and in the `tests/` directories of each crate.
//!
//! # Quick explanation of each module in ascending order of abstraction
//!
//! ## `core`
//!
//! Contains all the [necessary data structures] what Symbol & Nis1 have in common.
//!
//! ## `crypto-sym`
//!
//! Symbol Bockchain crypto library, along with cryptographic utilities for signing and
//! verifying Edwards Digital Signature Algorithm (EdDSA) over Curve25519.
//!
//! ## `crypto-nis1`
//!
//! Nis1 Bockchain crypto library, along with cryptographic utilities for signing and
//! verifying Edwards Digital Signature Algorithm (EdDSA) over Curve25519.
//!

#[cfg(feature = "nis1")]
pub use nis1_crypto as nis1;
pub use sym_crypto as sym;

/// Easy imports of frequently used type definitions and traits
///
#[doc(hidden)]
pub mod prelude {
    pub use core_crypto::*;

    #[cfg(feature = "nis1")]
    pub use nis1_crypto::CryptoNis1;
    #[cfg(feature = "nis1")]
    pub type KpNis1 = nis1_crypto::keypair::Keypair;

    pub use sym_crypto::CryptoSym;
    pub type KpSym = sym_crypto::keypair::Keypair;
}
