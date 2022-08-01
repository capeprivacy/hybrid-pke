use hacspec_lib::{ByteSeq, Seq, U8};
use hpke::{
    AdditionalData, Ciphertext, HPKECiphertext, HPKEConfig, HpkeOpen, HpkePrivateKey,
    HpkePublicKey, HpkeSeal, KemOutput, Mode,
};
use hpke_aead::AEAD;
use hpke_errors::HpkeError;
use hpke_kdf::{Info, InputKeyMaterial, KDF};
use hpke_kem::{DeriveKeyPair, Nsk, Randomness, KEM};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::{rngs::OsRng, RngCore};

fn get_default_hpke_config() -> HPKEConfig {
    let mode = Mode::mode_base;
    let kem = KEM::DHKEM_X25519_HKDF_SHA256;
    let kdf = KDF::HKDF_SHA256;
    let aead = AEAD::ChaCha20Poly1305;
    HPKEConfig(mode, kem, kdf, aead)
}

fn hpke_open_bytes(ctxtb: &[u8], skb: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let hpke_config = get_default_hpke_config();
    let kem_output = KemOutput::from_public_slice(&ctxtb[..32]);
    let ctxt = Ciphertext::from_public_slice(&ctxtb[32..]);
    let ciphertext = HPKECiphertext(kem_output, ctxt);
    let sk_r = HpkePrivateKey::from_public_slice(skb);
    let info = Info::new(0);
    let aad = AdditionalData::new(0);
    let result: ByteSeq = HpkeOpen(
        hpke_config,
        &ciphertext,
        &sk_r,
        &info,
        &aad,
        None,
        None,
        None,
    )?;
    let plaintext = result.into_native();
    Ok(plaintext)
}

fn hpke_seal_bytes(pkb: &[u8], ptxtb: &[u8]) -> Result<Vec<u8>, HpkeError> {
    let hpke_config = get_default_hpke_config();
    let pk = HpkePublicKey::from_public_slice(pkb);
    let ptxt = Seq::<U8>::from_public_slice(ptxtb);
    let info = Info::new(0);
    let aad = AdditionalData::new(0);
    let mut rand_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut rand_bytes);
    let randomness = Randomness::from_public_slice(&rand_bytes);
    let result: HPKECiphertext = HpkeSeal(
        hpke_config,
        &pk,
        &info,
        &aad,
        &ptxt,
        None,
        None,
        None,
        randomness,
    )?;
    let mut encapsulated: Vec<u8> = result.0.into_native();
    let mut ciphertext = result.1.into_native();
    encapsulated.append(&mut ciphertext);
    Ok(encapsulated)
}

fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let hpke_config = get_default_hpke_config();
    let kem = hpke_config.1;
    let nbytes = Nsk(kem);
    let mut rand_bytes = vec![0u8; nbytes];
    OsRng.fill_bytes(&mut rand_bytes);
    let randomness = InputKeyMaterial::from_public_slice(&rand_bytes);
    let keypair = DeriveKeyPair(kem, &randomness)?;
    Ok((keypair.0.into_native(), keypair.1.into_native()))
}

#[pyfunction]
fn generate_hpke_keypair(py: Python) -> PyResult<(&PyBytes, &PyBytes)> {
    let keypair_bytes = generate_keypair()
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:?}")))?;
    let sk_py = PyBytes::new(py, &keypair_bytes.0);
    let pk_py = PyBytes::new(py, &keypair_bytes.1);
    Ok((sk_py, pk_py))
}

/// Python binding to hpke-spec's Single-Shot API function hpke::HpkeSeal
#[pyfunction]
fn hpke_seal<'p>(py: Python<'p>, pk_py: &PyBytes, ptxt_py: &PyBytes) -> PyResult<&'p PyBytes> {
    let pkb = pk_py.as_bytes();
    let ptxtb = ptxt_py.as_bytes();
    let ciphertext_bytes = hpke_seal_bytes(pkb, ptxtb)
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:?}")))?;
    Ok(PyBytes::new(py, &ciphertext_bytes))
}

/// Python binding to hpke-spec's Single-Shot API function hpke::HpkeOpen
#[pyfunction]
fn hpke_open<'p>(py: Python<'p>, sk_py: &PyBytes, ctxt_py: &PyBytes) -> PyResult<&'p PyBytes> {
    let skb = sk_py.as_bytes();
    let ctxtb = ctxt_py.as_bytes();
    let plaintext_bytes = hpke_open_bytes(ctxtb, skb)
        .map_err(|hpke_error| PyRuntimeError::new_err(format!("{hpke_error:?}")))?;
    Ok(PyBytes::new(py, &plaintext_bytes))
}

/// A Python module implemented in Rust.
#[pymodule]
fn hpke_spec(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_hpke_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(hpke_open, m)?)?;
    m.add_function(wrap_pyfunction!(hpke_seal, m)?)?;
    Ok(())
}
