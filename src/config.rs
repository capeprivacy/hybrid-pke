use hpke_rs::{Hpke as HpkeRs, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use pyo3::prelude::*;
use std::convert::Into;

type Hpke = HpkeRs<HpkeRustCrypto>;

// Construct a reasonable default HPKEConfig
#[pyfunction]
pub(crate) fn default_config() -> PyHpke {
    let mode = PyMode::BASE;
    let kem = PyKemAlgorithm::DHKEM_X25519;
    let kdf = PyKdfAlgorithm::HKDF_SHA256;
    let aead = PyAeadAlgorithm::CHACHA20_POLY1305;
    PyHpke {
        mode,
        kem,
        kdf,
        aead,
    }
}

// Hpke contains the HPKE mode and ciphersuite needed to fully-specify & configure HPKE encryption.
#[pyclass]
#[pyo3(name = "Hpke", module = "hpke")]
#[derive(Clone)]
pub(crate) struct PyHpke {
    #[pyo3(get, set)]
    mode: PyMode,
    #[pyo3(get, set)]
    kem: PyKemAlgorithm,
    #[pyo3(get, set)]
    kdf: PyKdfAlgorithm,
    #[pyo3(get, set)]
    aead: PyAeadAlgorithm,
}

#[pymethods]
impl PyHpke {
    #[new]
    fn new(mode: PyMode, kem: PyKemAlgorithm, kdf: PyKdfAlgorithm, aead: PyAeadAlgorithm) -> Self {
        PyHpke {
            mode,
            kem,
            kdf,
            aead,
        }
    }
}

impl From<PyHpke> for Hpke {
    fn from(pyconfig: PyHpke) -> Self {
        Hpke::new(
            pyconfig.mode.into(),
            pyconfig.kem.into(),
            pyconfig.kdf.into(),
            pyconfig.aead.into(),
        )
    }
}

#[pyclass]
#[pyo3(name = "Mode", module = "hpke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyMode {
    BASE,
    PSK,
    AUTH,
    AUTH_PSK,
}

impl From<PyMode> for Mode {
    fn from(pymode: PyMode) -> Self {
        match pymode {
            PyMode::BASE => Mode::Base,
            PyMode::PSK => Mode::Psk,
            PyMode::AUTH => Mode::Auth,
            PyMode::AUTH_PSK => Mode::AuthPsk,
        }
    }
}

#[pyclass]
#[pyo3(name = "Kem", module = "hpke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKemAlgorithm {
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X25519,
    DHKEM_X448,
}

impl From<PyKemAlgorithm> for KemAlgorithm {
    fn from(pykem: PyKemAlgorithm) -> Self {
        match pykem {
            PyKemAlgorithm::DHKEM_P256 => KemAlgorithm::DhKemP256,
            PyKemAlgorithm::DHKEM_P384 => KemAlgorithm::DhKemP384,
            PyKemAlgorithm::DHKEM_P521 => KemAlgorithm::DhKemP521,
            PyKemAlgorithm::DHKEM_X25519 => KemAlgorithm::DhKem25519,
            PyKemAlgorithm::DHKEM_X448 => KemAlgorithm::DhKem448,
        }
    }
}

#[pyclass]
#[pyo3(name = "Kdf", module = "hpke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKdfAlgorithm {
    HKDF_SHA256,
    HKDF_SHA384,
    HKDF_SHA512,
}

impl From<PyKdfAlgorithm> for KdfAlgorithm {
    fn from(pykdf: PyKdfAlgorithm) -> Self {
        match pykdf {
            PyKdfAlgorithm::HKDF_SHA256 => KdfAlgorithm::HkdfSha256,
            PyKdfAlgorithm::HKDF_SHA384 => KdfAlgorithm::HkdfSha384,
            PyKdfAlgorithm::HKDF_SHA512 => KdfAlgorithm::HkdfSha512,
        }
    }
}

#[pyclass]
#[pyo3(name = "Aead", module = "hpke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyAeadAlgorithm {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    HPKE_EXPORT,
}

impl From<PyAeadAlgorithm> for AeadAlgorithm {
    fn from(pyaead: PyAeadAlgorithm) -> Self {
        match pyaead {
            PyAeadAlgorithm::AES_128_GCM => AeadAlgorithm::Aes128Gcm,
            PyAeadAlgorithm::AES_256_GCM => AeadAlgorithm::Aes256Gcm,
            PyAeadAlgorithm::CHACHA20_POLY1305 => AeadAlgorithm::ChaCha20Poly1305,
            PyAeadAlgorithm::HPKE_EXPORT => AeadAlgorithm::HpkeExport,
        }
    }
}
