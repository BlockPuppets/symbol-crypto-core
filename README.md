# Symbol & Nis1 Crypto Rust library.

# symbol-crypto-core

Fast and efficient Rust implementation of Symbol & Nis1 Blockchain crypto.

# Installation

To install, add the following to your project's `Cargo.toml`:

default sym support

```toml
[dependencies.symbol-crypto-core]
version = "0.1.1-alpha.2"
```

for nis1 support

```toml
[dependencies.symbol-crypto-core]
version = "0.1.1-alpha.2"
features = ['nis1']
```

for mnemonic support

```toml
[dependencies.symbol-crypto-core]
version = "0.1.1-alpha.2"
features = ['with_mnemonic']
```

## License

Licensed under the [Apache License 2.0](LICENSE)