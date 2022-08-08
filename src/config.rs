use hpke_rs::Mode;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use pyo3::prelude::*;

#[pyclass]
#[pyo3(name = "Mode", module = "hybrid_pke")]
#[derive(Clone)]
#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
pub(crate) enum PyMode {
    BASE,
    PSK,
    AUTH,
    AUTH_PSK,
}

impl From<&PyMode> for Mode {
    fn from(pymode: &PyMode) -> Self {
        match pymode {
            PyMode::BASE => Mode::Base,
            PyMode::PSK => Mode::Psk,
            PyMode::AUTH => Mode::Auth,
            PyMode::AUTH_PSK => Mode::AuthPsk,
        }
    }
}

#[pyclass]
#[pyo3(name = "Kem", module = "hybrid_pke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKemAlgorithm {
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X25519,
    DHKEM_X448,
}

impl From<&PyKemAlgorithm> for KemAlgorithm {
    fn from(pykem: &PyKemAlgorithm) -> Self {
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
#[pyo3(name = "Kdf", module = "hybrid_pke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKdfAlgorithm {
    HKDF_SHA256,
    HKDF_SHA384,
    HKDF_SHA512,
}

impl From<&PyKdfAlgorithm> for KdfAlgorithm {
    fn from(pykdf: &PyKdfAlgorithm) -> Self {
        match pykdf {
            PyKdfAlgorithm::HKDF_SHA256 => KdfAlgorithm::HkdfSha256,
            PyKdfAlgorithm::HKDF_SHA384 => KdfAlgorithm::HkdfSha384,
            PyKdfAlgorithm::HKDF_SHA512 => KdfAlgorithm::HkdfSha512,
        }
    }
}

#[pyclass]
#[pyo3(name = "Aead", module = "hybrid_pke")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyAeadAlgorithm {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    HPKE_EXPORT,
}

impl From<&PyAeadAlgorithm> for AeadAlgorithm {
    fn from(pyaead: &PyAeadAlgorithm) -> Self {
        match pyaead {
            PyAeadAlgorithm::AES_128_GCM => AeadAlgorithm::Aes128Gcm,
            PyAeadAlgorithm::AES_256_GCM => AeadAlgorithm::Aes256Gcm,
            PyAeadAlgorithm::CHACHA20_POLY1305 => AeadAlgorithm::ChaCha20Poly1305,
            PyAeadAlgorithm::HPKE_EXPORT => AeadAlgorithm::HpkeExport,
        }
    }
}
