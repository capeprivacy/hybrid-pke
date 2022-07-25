py-hpke-spec
===============
The Hybrid Public Key Encryption (HPKE) standard in Python.

- [`hpke-spec`](https://github.com/cryspen/hpke-spec) = [HPKE](https://blog.cloudflare.com/hybrid-public-key-encryption/) :handshake: [`hacspec`](https://hacspec.github.io)

- [`py-hpke-spec`](https://github.com/capeprivacy/py-hpke-spec) = [`hpke-spec`](https://github.com/cryspen/hpke-spec) :handshake: [`PyO3`](https://github.com/PyO3/pyo3)


This HPKE implementation is simply a thin Python wrapper around [`hpke-spec`](https://github.com/cryspen/hpke-spec), the hacspec implementation [written by Franziskus Kiefer](https://www.franziskuskiefer.de/p/tldr-hybrid-public-key-encryption/). This package mirrors the `hpke-spec` constructions as much as possible, to avoid any discrepancy from the HPKE standard.

## Why `hpke-spec`?

The `hpke-spec` library has two primary advantages:
- `hpke-spec` is written in [`hacspec`](https://hacspec.github.io/) which can be compiled into [F*](https://www.fstar-lang.org/) for formal verification.
- The cargo [documentation](https://tech.cryspen.com/hpke-spec/hpke/index.html) for `hpke-spec` is simply the text of the [HPKE RFC 9180](https://datatracker.ietf.org/doc/rfc9180/), with all the RFC's constructions linked directly to the hacspec code that implements it.

As a result, it's much more straightforward to evaluate `hpke-spec` for security and correctness. Indeed, both hacspec and RFC 9180 have received thorough vetting from cryptographers in [Project Everest](https://project-everest.github.io) and the [Internet Research Task Force](https://datatracker.ietf.org/doc/rfc9180/), respectively.

## Installation
Wheels for various platforms and architectures can be found in the `wheelhouse.zip` archive from [latest Github release](https://github.com/capeprivacy/py-hpke-spec/releases).

THe library can also be installed from source with [`maturin`](https://github.com/PyO3/maturin); see below.

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
