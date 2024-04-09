use pyo3::prelude::*;
// use rand::{rngs::OsRng, RngCore};

mod config;
mod context;
mod errors;
mod hpke;
use crate::config::*;
use crate::context::PyContext;
use crate::errors::*;
use crate::hpke::*;

/// Construct a reasonable default HPKEConfig
#[pyfunction]
#[pyo3(signature = (mode = None, kem = None, kdf = None, aead = None))]
pub(crate) fn default(
    mode: Option<PyMode>,
    kem: Option<PyKemAlgorithm>,
    kdf: Option<PyKdfAlgorithm>,
    aead: Option<PyAeadAlgorithm>,
) -> PyHpke {
    let mode = mode.unwrap_or(PyMode::BASE);
    let kem = kem.unwrap_or(PyKemAlgorithm::DHKEM_X25519);
    let kdf = kdf.unwrap_or(PyKdfAlgorithm::HKDF_SHA256);
    let aead = aead.unwrap_or(PyAeadAlgorithm::CHACHA20_POLY1305);
    PyHpke::new(mode, kem, kdf, aead)
}

fn build_errors_module(py: Python) -> PyResult<Bound<PyModule>> {
    let errors_module = PyModule::new_bound(py, "errors")?;
    errors_module.add("OpenError", py.get_type_bound::<OpenError>())?;
    errors_module.add("InvalidConfig", py.get_type_bound::<InvalidConfig>())?;
    errors_module.add("InvalidInput", py.get_type_bound::<InvalidInput>())?;
    errors_module.add("UnknownMode", py.get_type_bound::<UnknownMode>())?;
    errors_module.add("InconsistentPsk", py.get_type_bound::<InconsistentPsk>())?;
    errors_module.add("MissingPsk", py.get_type_bound::<MissingPsk>())?;
    errors_module.add("UnnecessaryPsk", py.get_type_bound::<UnnecessaryPsk>())?;
    errors_module.add("InsecurePsk", py.get_type_bound::<InsecurePsk>())?;
    errors_module.add("CryptoError", py.get_type_bound::<CryptoError>())?;
    errors_module.add("MessageLimitReached", py.get_type_bound::<MessageLimitReached>())?;
    errors_module.add(
        "InsufficientRandomness",
        py.get_type_bound::<InsufficientRandomness>(),
    )?;
    Ok(errors_module)
}

/// PyO3 module for hpke.
#[pymodule]
fn hybrid_pke(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    let errors_module = build_errors_module(py)?;
    m.add_submodule(&errors_module)?;
    m.add_class::<PyHpke>()?;
    m.add_class::<PyContext>()?;
    m.add_class::<PyMode>()?;
    m.add_class::<PyKemAlgorithm>()?;
    m.add_class::<PyKdfAlgorithm>()?;
    m.add_class::<PyAeadAlgorithm>()?;
    m.add_function(wrap_pyfunction!(default, m)?)?;
    Ok(())
}
