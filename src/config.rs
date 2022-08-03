use hpke::{HPKEConfig, Mode};
use hpke_aead::AEAD;
use hpke_kdf::KDF;
use hpke_kem::KEM;
use pyo3::prelude::*;
use std::convert::Into;

// Construct a reasonable default HPKEConfig
#[pyfunction]
pub(crate) fn default_config() -> PyHPKEConfig {
    let mode = PyMode::mode_base;
    let kem = PyKEM::DHKEM_X25519_HKDF_SHA256;
    let kdf = PyKDF::HKDF_SHA256;
    let aead = PyAEAD::ChaCha20Poly1305;
    PyHPKEConfig {
        mode,
        kem,
        kdf,
        aead,
    }
}

// HPKEConfig contains the HPKE mode and ciphersuite needed to fully-specify & configure HPKE encryption.
#[pyclass]
#[pyo3(name = "HPKEConfig", module = "hpke_spec")]
#[derive(Clone)]
pub(crate) struct PyHPKEConfig {
    #[pyo3(get, set)]
    mode: PyMode,
    #[pyo3(get, set)]
    kem: PyKEM,
    #[pyo3(get, set)]
    kdf: PyKDF,
    #[pyo3(get, set)]
    aead: PyAEAD,
}

#[pymethods]
impl PyHPKEConfig {
    #[new]
    fn new(mode: PyMode, kem: PyKEM, kdf: PyKDF, aead: PyAEAD) -> Self {
        PyHPKEConfig {
            mode,
            kem,
            kdf,
            aead,
        }
    }
}

impl From<PyHPKEConfig> for HPKEConfig {
    fn from(pyconfig: PyHPKEConfig) -> Self {
        HPKEConfig(
            pyconfig.mode.into(),
            pyconfig.kem.into(),
            pyconfig.kdf.into(),
            pyconfig.aead.into(),
        )
    }
}

#[pyclass]
#[pyo3(name = "Mode", module = "hpke_spec")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyMode {
    mode_base,
    mode_psk,
    mode_auth,
    mode_auth_psk,
}

impl From<PyMode> for Mode {
    fn from(pymode: PyMode) -> Self {
        match pymode {
            PyMode::mode_base => Mode::mode_base,
            PyMode::mode_psk => Mode::mode_psk,
            PyMode::mode_auth => Mode::mode_auth,
            PyMode::mode_auth_psk => Mode::mode_auth_psk,
        }
    }
}

#[pyclass]
#[pyo3(name = "KEM", module = "hpke_spec")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKEM {
    DHKEM_P256_HKDF_SHA256,
    DHKEM_P384_HKDF_SHA384,
    DHKEM_P521_HKDF_SHA512,
    DHKEM_X25519_HKDF_SHA256,
    DHKEM_X448_HKDF_SHA512,
}

impl From<PyKEM> for KEM {
    fn from(pykem: PyKEM) -> Self {
        match pykem {
            PyKEM::DHKEM_P256_HKDF_SHA256 => KEM::DHKEM_P256_HKDF_SHA256,
            PyKEM::DHKEM_P384_HKDF_SHA384 => KEM::DHKEM_P384_HKDF_SHA384,
            PyKEM::DHKEM_P521_HKDF_SHA512 => KEM::DHKEM_P521_HKDF_SHA512,
            PyKEM::DHKEM_X25519_HKDF_SHA256 => KEM::DHKEM_X25519_HKDF_SHA256,
            PyKEM::DHKEM_X448_HKDF_SHA512 => KEM::DHKEM_X448_HKDF_SHA512,
        }
    }
}

#[pyclass]
#[pyo3(name = "KDF", module = "hpke_spec")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyKDF {
    HKDF_SHA256,
    HKDF_SHA384,
    HKDF_SHA512,
}

impl From<PyKDF> for KDF {
    fn from(pykdf: PyKDF) -> Self {
        match pykdf {
            PyKDF::HKDF_SHA256 => KDF::HKDF_SHA256,
            PyKDF::HKDF_SHA384 => KDF::HKDF_SHA384,
            PyKDF::HKDF_SHA512 => KDF::HKDF_SHA512,
        }
    }
}

#[pyclass]
#[pyo3(name = "AEAD", module = "hpke_spec")]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub(crate) enum PyAEAD {
    AES_128_GCM,
    AES_256_GCM,
    ChaCha20Poly1305,
    Export_only,
}

impl From<PyAEAD> for AEAD {
    fn from(pyaead: PyAEAD) -> Self {
        match pyaead {
            PyAEAD::AES_128_GCM => AEAD::AES_128_GCM,
            PyAEAD::AES_256_GCM => AEAD::AES_256_GCM,
            PyAEAD::ChaCha20Poly1305 => AEAD::ChaCha20Poly1305,
            PyAEAD::Export_only => AEAD::Export_only,
        }
    }
}
