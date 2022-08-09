hybrid-pke
===============
The Hybrid Public Key Encryption (HPKE) standard in Python.

[`hpke-rs`](https://crates.io/crates/hpke-rs) :handshake: [`PyO3`](https://github.com/PyO3/pyo3)

This library provides Python bindings to the `hpke-rs` crate, which supports primitives from either [Rust Crypto](https://github.com/RustCrypto) or [EverCrypt](https://hacl-star.github.io/HaclValeEverCrypt.html).

## Features
The modes and features available match those supported by `hpke-rs`.

 - Modes
   - [x] mode_base
   - [x] mode_psk
   - [x] mode_auth
   - [x] mode_auth_psk
 - AEADs
   - [x] AES-128-GCM
   - [x] AES-256-GCM
   - [x] ChaCha20Poly1305
   - [ ] Export only
 - KEMs
   - [x] DHKEM(P-256, HKDF-SHA256)
   - [ ] DHKEM(P-384, HKDF-SHA384)
   - [ ] DHKEM(P-521, HKDF-SHA512)
   - [x] DHKEM(X25519, HKDF-SHA256)
   - [ ] DHKEM(X448, HKDF-SHA512)
 - KDFs
   - [x] HKDF-SHA256
   - [x] HKDF-SHA384
   - [x] HKDF-SHA512


## Installation
Wheels for various platforms and architectures can be found on [PyPI](https://pypi.org/project/hpke-spec/) or in the `wheelhouse.zip` archive from the [latest Github release](https://github.com/capeprivacy/py-hpke-spec/releases).

The library can also be installed from source with [`maturin`](https://github.com/PyO3/maturin) -- see below.

## Development

We use [`maturin`](https://github.com/PyO3/maturin) to build and distribute the PyO3 extension module as a Python wheel.

For users of `cmake`, we provide a [`Makefile`](https://github.com/capeprivacy/py-hpke-spec/blob/main/Makefile) that includes some helpful development commands.

Other useful tips:
- `maturin develop` builds & installs the Python package into your Python environment (`venv` or `conda` recommended)
- `pytest .` tests the resulting Python package
- `maturin build --release -o dist --sdist` builds the extension module in release-mode and produces a wheel for your environment's OS and architecture.
- The `-i`/`--interpreter` flag for `maturin` can be used to swap out different Python interpreters, if you have multiple Python installations.

## Related Projects
- [hpke-py](https://github.com/ctz/hpke-py): An implementation of HPKE based on primitives from [cryptography.io](https://cryptography.io).
