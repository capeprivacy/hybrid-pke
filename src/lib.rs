use hacspec_lib::{ByteSeq, Seq, U8};
use hpke::{
    AdditionalData, Ciphertext, HPKECiphertext, HPKEConfig, HpkeOpen, HpkePrivateKey,
    HpkePublicKey, HpkeSeal, KemOutput,
};
use hpke_errors::HpkeError;
use hpke_kdf::Info;
use hpke_kem::{GenerateKeyPair, Nenc, Nsk, Randomness, SerializePublicKey, KEM};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::{rngs::OsRng, RngCore};

pub mod config;
use crate::config::*;

fn hpke_open_bytes(config: HPKEConfig, ctxtb: &[u8], skb: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let kem = config.1;
    let n_enc = Nenc(kem);
    let kem_output = KemOutput::from_public_slice(&ctxtb[..n_enc]);
    let ctxt = Ciphertext::from_public_slice(&ctxtb[n_enc..]);
    let ciphertext = HPKECiphertext(kem_output, ctxt);
    let sk_r = HpkePrivateKey::from_public_slice(skb);
    let info = Info::new(0);
    let aad = AdditionalData::new(0);
    let result: ByteSeq = HpkeOpen(config, &ciphertext, &sk_r, &info, &aad, None, None, None)?;
    let plaintext = result.into_native();
    Ok(plaintext)
}

fn hpke_seal_bytes(config: HPKEConfig, pkb: &[u8], ptxtb: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let pk = HpkePublicKey::from_public_slice(pkb);
    let ptxt = Seq::<U8>::from_public_slice(ptxtb);
    let info = Info::new(0);
    let aad = AdditionalData::new(0);
    let mut rand_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let randomness = Randomness::from_public_slice(&rand_bytes);
    let result: HPKECiphertext = HpkeSeal(
        config, &pk, &info, &aad, &ptxt, None, None, None, randomness,
    )?;
    let mut encapsulated: Vec<u8> = result.0.into_native();
    let mut ciphertext = result.1.into_native();
    encapsulated.append(&mut ciphertext);
    Ok(encapsulated)
}

fn generate_keypair(kem: KEM) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let nbytes = Nsk(kem);
    let mut rand_bytes = vec![0u8; nbytes];
    OsRng.fill_bytes(&mut rand_bytes);
    let randomness = Randomness::from_public_slice(&rand_bytes);
    let keypair = GenerateKeyPair(kem, randomness)?;
    let priv_key = keypair.0;
    let pub_key = SerializePublicKey(kem, &keypair.1);
    Ok((priv_key.into_native(), pub_key.into_native()))
}

#[pyfunction]
#[pyo3(name = "generate_keypair")]
fn generate_keypair_py(py: Python, kem: PyKEM) -> PyResult<(&PyBytes, &PyBytes)> {
    let keypair_bytes = generate_keypair(kem.into())
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:#?}")))?;
    let sk_py = PyBytes::new(py, &keypair_bytes.0);
    let pk_py = PyBytes::new(py, &keypair_bytes.1);
    Ok((sk_py, pk_py))
}

/// PyO3 binding to hpke-spec's Single-Shot API function hpke::HpkeSeal
#[pyfunction]
fn seal<'p>(
    py: Python<'p>,
    pk_py: &PyBytes,
    ptxt_py: &PyBytes,
    config_py: PyHPKEConfig,
) -> PyResult<&'p PyBytes> {
    let pkb = pk_py.as_bytes();
    let ptxtb = ptxt_py.as_bytes();
    let ciphertext_bytes = hpke_seal_bytes(config_py.into(), pkb, ptxtb)
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:#?}")))?;
    Ok(PyBytes::new(py, &ciphertext_bytes))
}

/// PyO3 binding to hpke-spec's Single-Shot API function hpke::HpkeOpen
#[pyfunction]
fn open<'p>(
    py: Python<'p>,
    sk_py: &PyBytes,
    ctxt_py: &PyBytes,
    config_py: PyHPKEConfig,
) -> PyResult<&'p PyBytes> {
    let skb = sk_py.as_bytes();
    let ctxtb = ctxt_py.as_bytes();
    let plaintext_bytes = hpke_open_bytes(config_py.into(), ctxtb, skb)
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:#?}")))?;
    Ok(PyBytes::new(py, &plaintext_bytes))
}

/// PyO3 module for hpke-spec.
#[pymodule]
fn hpke_spec(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyHPKEConfig>()?;
    m.add_class::<PyAEAD>()?;
    m.add_class::<PyKDF>()?;
    m.add_class::<PyKEM>()?;
    m.add_class::<PyMode>()?;
    m.add_function(wrap_pyfunction!(default_config, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair_py, m)?)?;
    m.add_function(wrap_pyfunction!(open, m)?)?;
    m.add_function(wrap_pyfunction!(seal, m)?)?;
    Ok(())
}
