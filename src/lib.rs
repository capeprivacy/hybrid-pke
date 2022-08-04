use pyo3::prelude::*;
// use rand::{rngs::OsRng, RngCore};

mod config;
mod errors;
mod hpke;
use crate::config::*;
use crate::errors::*;
use crate::hpke::*;

// Construct a reasonable default HPKEConfig
#[pyfunction]
pub(crate) fn default_config() -> PyHpke {
    let mode = PyMode::BASE;
    let kem = PyKemAlgorithm::DHKEM_X25519;
    let kdf = PyKdfAlgorithm::HKDF_SHA256;
    let aead = PyAeadAlgorithm::CHACHA20_POLY1305;
    PyHpke::new(mode, kem, kdf, aead)
}

// fn hpke_open_bytes(config: HPKEConfig, ctxtb: &[u8], skb: &[u8]) -> Result<Vec<u8>, HpkeError> {
//     let kem = config.1;
//     let n_enc = Nenc(kem);
//     let kem_output = KemOutput::from_public_slice(&ctxtb[..n_enc]);
//     let ctxt = Ciphertext::from_public_slice(&ctxtb[n_enc..]);
//     let ciphertext = HPKECiphertext(kem_output, ctxt);
//     let sk_r = HpkePrivateKey::from_public_slice(skb);
//     let info = Info::new(0);
//     let aad = AdditionalData::new(0);
//     let result: ByteSeq = HpkeOpen(config, &ciphertext, &sk_r, &info, &aad, None, None, None)?;
//     let plaintext = result.into_native();
//     Ok(plaintext)
// }

// /// PyO3 binding to hpke-spec's Single-Shot API function hpke::HpkeOpen
// #[pyfunction]
// fn open<'p>(
//     py: Python<'p>,
//     sk_py: &PyBytes,
//     ctxt_py: &PyBytes,
//     config_py: PyHPKEConfig,
// ) -> PyResult<&'p PyBytes> {
//     let skb = sk_py.as_bytes();
//     let ctxtb = ctxt_py.as_bytes();
//     let plaintext_bytes = hpke_open_bytes(config_py.into(), ctxtb, skb)
//         .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:#?}")))?;
//     Ok(PyBytes::new(py, &plaintext_bytes))
// }

fn build_errors_module(py: Python) -> PyResult<&PyModule> {
    let errors_module = PyModule::new(py, "errors")?;
    errors_module.add("OpenError", py.get_type::<OpenError>())?;
    errors_module.add("InvalidConfig", py.get_type::<InvalidConfig>())?;
    errors_module.add("InvalidInput", py.get_type::<InvalidInput>())?;
    errors_module.add("UnknownMode", py.get_type::<UnknownMode>())?;
    errors_module.add("InconsistentPsk", py.get_type::<InconsistentPsk>())?;
    errors_module.add("MissingPsk", py.get_type::<MissingPsk>())?;
    errors_module.add("UnnecessaryPsk", py.get_type::<UnnecessaryPsk>())?;
    errors_module.add("InsecurePsk", py.get_type::<InsecurePsk>())?;
    errors_module.add("CryptoError", py.get_type::<CryptoError>())?;
    errors_module.add("MessageLimitReached", py.get_type::<MessageLimitReached>())?;
    errors_module.add(
        "InsufficientRandomness",
        py.get_type::<InsufficientRandomness>(),
    )?;
    errors_module.add("LockPoisoned", py.get_type::<LockPoisoned>())?;
    Ok(errors_module)
}

/// PyO3 module for hpke-spec.
#[pymodule]
#[pyo3(name = "hpke")]
fn pyhpke(py: Python, m: &PyModule) -> PyResult<()> {
    let errors_module = build_errors_module(py)?;
    m.add_submodule(errors_module)?;
    m.add_class::<PyHpke>()?;
    m.add_class::<PyMode>()?;
    m.add_class::<PyKemAlgorithm>()?;
    m.add_class::<PyKdfAlgorithm>()?;
    m.add_class::<PyAeadAlgorithm>()?;
    m.add_function(wrap_pyfunction!(default_config, m)?)?;
    // m.add_function(wrap_pyfunction!(open, m)?)?;
    // m.add_function(wrap_pyfunction!(seal, m)?)?;
    Ok(())
}
