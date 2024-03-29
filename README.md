Hybrid PKE
===============
The Hybrid Public Key Encryption (HPKE) standard in Python.

`hybrid_pke` = [`hpke-rs`](https://github.com/franziskuskiefer/hpke-rs) :heavy_plus_sign: [`PyO3`](https://github.com/PyO3/pyo3)

This library provides Python bindings to the `hpke-rs` crate, which supports primitives from either [Rust Crypto](https://github.com/RustCrypto) or [EverCrypt](https://hacl-star.github.io/HaclValeEverCrypt.html).

<details>
  <summary> Table of Contents </summary>
  <ol>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#development">Development</a></li>
    <li><a href="#related-projects">Related Projects</a></li>
  </ol>
</details>

## Usage
### Basic
The single-shot API is intended for single message encryption/decryption. The default HPKE configuration uses the unauthenticated Base mode, an X25519 DH key encapsulation mechanism, a SHA256 key derivation mechanism, and a ChaCha20Poly1305 AEAD function.

```python
import hybrid_pke

hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level
secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys, pre-generated

# ============== Sender ==============

message = b"hello from the other side!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message)

# ============= Receiver =============

plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext)
print(plaintext.decode("utf-8"))
# >> hello from the other side!
```

### Advanced

<details><summary> Sender & Receiver Contexts </summary>

The Sender Context and Receiver Context APIs allow for setting up a context for repeated encryptions and decryptions. It's recommended whenever you intend to perform several encryptions or decryptions in quick succession.
```python
info = b"quotes from your favorite aphorists"
aads = [
  b"Szasz",
  b"Nietzsche",
  b"Morandotti",
  b"Brudzinski",
  b"Hubbard",
]

# ============== Sender ==============

messages = [
    b"Two wrongs don't make a right, but they make a good excuse.",
    b"Become who you are!",
    b"Only those who aren't hungry are able to judge the quality of a meal.",
    b"Under certain circumstances a wanted poster is a letter of recommendation.",
    b"Nobody ever forgets where he buried the hatchet.",
]
encap, sender_context = hpke.setup_sender(public_key_r, info)

ciphertexts = []
for aad, msg in zip(aads, messages):
    ciphertext = sender_context.seal(aad, msg)
    ciphertexts.append(ciphertext)

# ============= Receiver =============

receiver_context = hpke.setup_receiver(encap, secret_key_r, info)
plaintexts = []
for aad, ctxt in zip(aads, ciphertexts):
    plaintext = receiver_context.open(aad, ctxt)
    plaintexts.append(plaintext)

print(f"\"{plaintexts[0].decode()}\" - {aad[0].decode()}")
print(f"\"{plaintexts[1].decode()}\" - {aad[1].decode()}")
# >> "Two wrongs don't make a right, but they make a good excuse." - Szasz
# >> "Become who you are!" - Nietzsche
```
</details>

<details><summary> Mode.AUTH: Authenticated Sender </summary>

Auth mode allows for signing and verifying encryptions with a previously authenticated sender key-pair.
```python
hpke = hybrid_pke.default(mode=hybrid_pke.Mode.AUTH)
secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys
secret_key_s, public_key_s = hpke.generate_key_pair()  # sender keys, pre-authenticated

# ============== Sender ==============

# sign with sender's secret key
encap, ciphertext = hpke.seal(public_key_r, info, aad, message, sk_s=secret_key_s)

# ============= Receiver =============

# verify with sender's public key
plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext, pk_s=public_key_s)
```
</details>

<details><summary>Mode.PSK: Pre-shared Key Authentication</summary>

PSK mode allows for signing and verifying encryptions with a previously shared key held by both the sender and recipient.
```python
hpke = hybrid_pke.default(mode=hybrid_pke.Mode.PSK)
# pre-shared key + ID
psk = bytes.fromhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
psk_id = bytes.fromhex("456e6e796e20447572696e206172616e204d6f726961")

# ============== Sender ==============

# sign with pre-shared key
encap, ciphertext = hpke.seal(public_key_r, info, aad, message, psk=psk, psk_id=psk_id)

# ============= Receiver =============

# verify with pre-shared key
plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext, psk=psk, psk_id=psk_id)
```
</details>

<details><summary>Mode.AUTH_PSK: Combining AUTH and PSK. </summary>

PSK mode allows for signing and verifying encryptions with a previously shared key held by both the sender and recipient.
```python
hpke = hybrid_pke.default(mode=hybrid_pke.Mode.PSK)
secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys
secret_key_s, public_key_s = hpke.generate_key_pair()  # sender keys, pre-authenticated
# pre-shared key + ID
psk = bytes.fromhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
psk_id = bytes.fromhex("456e6e796e20447572696e206172616e204d6f726961")

# ============== Sender ==============

# sign with both pre-shared key and sender's secret key
encap, ciphertext = hpke.seal(
    public_key_r, info, aad, message,
    psk=psk, psk_id=psk_id, sk_s=secret_key_s,
)

# ============= Receiver =============

# verify with both pre-shared key and sender's public key
plaintext = hpke.open(
    encap, secret_key_r, info, aad, ciphertext,
    psk=psk, psk_id=psk_id, pk_s=public_key_s,
)
```
</details>

<p align="right">(<a href="#top">back to top</a>)</p>

## Features
The features available match those supported by `hpke-rs`.

<details><summary>HPKE Modes</summary>

- [x] mode_base
- [x] mode_psk
- [x] mode_auth
- [x] mode_auth_psk
</details>

<details><summary>KEMs: (Diffie-Hellman) Key Encapsulation Mechanisms</summary>

- [x] DHKEM(P-256, HKDF-SHA256)
- [ ] DHKEM(P-384, HKDF-SHA384)
- [ ] DHKEM(P-521, HKDF-SHA512)
- [x] DHKEM(X25519, HKDF-SHA256)
- [ ] DHKEM(X448, HKDF-SHA512)
</details>

<details><summary>KDFs: Key Derivation Functions </summary>

- [x] HKDF-SHA256
- [x] HKDF-SHA384
- [x] HKDF-SHA512
</details>

<details><summary>AEADs: Authenticated Encryption with Additional Data functions</summary>

- [x] AES-128-GCM
- [x] AES-256-GCM
- [x] ChaCha20Poly1305
- [x] Export only
</details>

<p align="right">(<a href="#top">back to top</a>)</p>

## Installation
Wheels for various platforms and architectures can be found on [PyPI](https://pypi.org/project/hybrid-pke/) or in the `wheelhouse.zip` archive from the [latest Github release](https://github.com/capeprivacy/hybrid-pke/releases).

The library can also be installed from source with [`maturin`](https://github.com/PyO3/maturin) -- see below.

<p align="right">(<a href="#top">back to top</a>)</p>

## Development

We use [`maturin`](https://github.com/PyO3/maturin) to build and distribute the PyO3 extension module as a Python wheel.

For users of `cmake`, we provide a [`Makefile`](https://github.com/capeprivacy/hybrid-pke/blob/main/Makefile) that includes some helpful development commands.

<details><summary>Some useful tips</summary>

- `maturin develop` builds & installs the Python package into your Python environment (`venv` or `conda` recommended)
- `pytest .` tests the resulting Python package.
- `pytest -n auto .` runs the full test suite in parallel.
- `maturin build --release -o dist --sdist` builds the extension module in release-mode and produces a wheel for your environment's OS and architecture.
- The `-i`/`--interpreter` flag for `maturin` can be used to swap out different Python interpreters, if you have multiple Python installations.
</details>

<p align="right">(<a href="#top">back to top</a>)</p>

## Releasing

We use [`cargo-release`](https://github.com/crate-ci/cargo-release) to manage release commits and git tags. Our versioning follows SemVer, and after every release we immediately bump to a prerelease version with the `-dev0` suffix.

<details><summary>Example release flow</summary>

```console
$ git checkout main
$ cargo release patch --execute
Upgrading hybrid_pke from X.X.X-dev0 to X.X.X
   Replacing in pyproject.toml
--- pyproject.toml      original
+++ pyproject.toml      replaced
@@ -8 +8 @@
-version = "X.X.X-dev0"  # NOTE: auto-updated during release
+version = "X.X.X"  # NOTE: auto-updated during release
$ cargo release X.X.Y-dev0 --no-tag
Upgrading hybrid_pke from X.X.X to X.X.Y-dev0
   Replacing in pyproject.toml
--- pyproject.toml      original
+++ pyproject.toml      replaced
@@ -8 +8 @@
-version = "X.X.X"  # NOTE: auto-updated during release
+version = "X.X.Y-dev0"  # NOTE: auto-updated during release
$ git push origin main
$ git push origin vX.X.X  # triggers automatic release steps in CI
```

</details>

<p align="right">(<a href="#top">back to top</a>)</p>

## Related Projects
- [hpke-py](https://github.com/ctz/hpke-py): An implementation of HPKE based on primitives from [cryptography.io](https://cryptography.io).

<p align="right">(<a href="#top">back to top</a>)</p>