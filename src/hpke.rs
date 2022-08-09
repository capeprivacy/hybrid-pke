use hpke_rs::HpkePrivateKey;
use hpke_rs::{Hpke as HpkeRs, HpkePublicKey};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::config::*;
use crate::context::PyContext;
use crate::errors::*;

pub(crate) type Hpke = HpkeRs<HpkeRustCrypto>;

/// Hpke defines the mode and ciphersuite needed to fully specify an HPKE configuration.
/// The resulting Hpke configuration object exposes the primary HPKE protocols as instance methods.
#[pyclass]
#[pyo3(name = "Hpke", module = "hybrid_pke")]
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
    pub fn new(
        mode: PyMode,
        kem: PyKemAlgorithm,
        kdf: PyKdfAlgorithm,
        aead: PyAeadAlgorithm,
    ) -> Self {
        PyHpke {
            mode,
            kem,
            kdf,
            aead,
        }
    }

    /// Set up an HPKE sender context
    #[args(psk = "None", psk_id = "None", sk_s = "None")]
    fn setup_sender<'p>(
        &self,
        py: Python<'p>,
        pk_r: &PyBytes,
        info: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        sk_s: Option<&PyBytes>,
    ) -> PyResult<(&'p PyBytes, PyContext)> {
        let cfg: Hpke = self.into();

        // convert args, drop py refs
        let pk_r = HpkePublicKey::new(pk_r.as_bytes().into());
        let info = info.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());

        // create sender context
        let (encap, context) = match sk_s {
            None => cfg.setup_sender(&pk_r, info, psk, psk_id, None),
            Some(sk) => {
                let sk = HpkePrivateKey::new(sk.as_bytes().into());
                cfg.setup_sender(&pk_r, info, psk, psk_id, Some(&sk))
            }
        }
        .map_err(handle_hpke_error)?;
        let encap_py = PyBytes::new(py, encap.as_slice());
        let context_py = PyContext::new(context);
        Ok((encap_py, context_py))
    }

    /// Set up an HPKE receiver context
    #[args(psk = "None", psk_id = "None", pk_s = "None")]
    fn setup_receiver(
        &self,
        enc: &PyBytes,
        sk_r: &PyBytes,
        info: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        pk_s: Option<&PyBytes>,
    ) -> PyResult<PyContext> {
        let cfg: Hpke = self.into();

        // convert args, drop py refs
        let enc = enc.as_bytes();
        let sk_r = HpkePrivateKey::new(sk_r.as_bytes().into());
        let info = info.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());

        // create receiver context
        let context = match pk_s {
            None => cfg.setup_receiver(enc, &sk_r, info, psk, psk_id, None),
            Some(pk) => {
                let pk = HpkePublicKey::new(pk.as_bytes().into());
                cfg.setup_receiver(enc, &sk_r, info, psk, psk_id, Some(&pk))
            }
        }
        .map_err(handle_hpke_error)?;

        Ok(PyContext::new(context))
    }

    /// Encrypt input, single-shot
    #[allow(clippy::too_many_arguments)]
    #[args(psk = "None", psk_id = "None", sk_s = "None")]
    fn seal<'p>(
        &self,
        py: Python<'p>,
        pk_r: &PyBytes,
        info: &PyBytes,
        aad: &PyBytes,
        plain_txt: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        sk_s: Option<&PyBytes>,
    ) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg: Hpke = self.into();

        // convert args, drop py refs
        let pk_r = HpkePublicKey::new(pk_r.as_bytes().into());
        let info = info.as_bytes();
        let aad = aad.as_bytes();
        let plain_txt = plain_txt.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());

        // perform single-shot seal
        let (encap, cipher_txt) = match sk_s {
            None => cfg.seal(&pk_r, info, aad, plain_txt, psk, psk_id, None),
            // if sk_s is Some(b), we need to take ownership to create HpkePrivateKey
            // so that we can give &HpkePrivateKey to Hpke::seal
            // TODO(jason) would be great if we could go from &[u8] to &HpkePrivateKey here
            Some(sk) => {
                let sk = HpkePrivateKey::new(sk.as_bytes().into());
                cfg.seal(&pk_r, info, aad, plain_txt, psk, psk_id, Some(&sk))
            }
        }
        .map_err(handle_hpke_error)?;

        // convert return vals back to PyBytes
        let encap_py = PyBytes::new(py, encap.as_slice());
        let cipher_txt_py = PyBytes::new(py, cipher_txt.as_slice());
        Ok((encap_py, cipher_txt_py))
    }

    /// Decrypt input, single-shot
    #[allow(clippy::too_many_arguments)]
    #[args(psk = "None", psk_id = "None", pk_s = "None")]
    fn open<'p>(
        &self,
        py: Python<'p>,
        enc: &PyBytes,
        sk_r: &PyBytes,
        info: &PyBytes,
        aad: &PyBytes,
        cipher_txt: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        pk_s: Option<&PyBytes>,
    ) -> PyResult<&'p PyBytes> {
        let cfg: Hpke = self.into();

        // convert args, drop py refs
        let enc = enc.as_bytes();
        let sk_r = HpkePrivateKey::new(sk_r.as_bytes().into());
        let info = info.as_bytes();
        let aad = aad.as_bytes();
        let cipher_txt = cipher_txt.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());

        // perform single-shot open
        let plain_txt = match pk_s {
            None => cfg.open(enc, &sk_r, info, aad, cipher_txt, psk, psk_id, None),
            // TODO(jason) would be great if we could go from &[u8] to &HpkePublicKey here
            Some(pk) => {
                let pk = HpkePublicKey::new(pk.as_bytes().into());
                cfg.open(enc, &sk_r, info, aad, cipher_txt, psk, psk_id, Some(&pk))
            }
        }
        .map_err(handle_hpke_error)?;

        // convert return val back to PyBytes
        let plain_txt_py = PyBytes::new(py, plain_txt.as_slice());
        Ok(plain_txt_py)
    }
}

impl From<&PyHpke> for Hpke {
    fn from(pyconfig: &PyHpke) -> Self {
        let mode = &pyconfig.mode;
        let kem = &pyconfig.kem;
        let kdf = &pyconfig.kdf;
        let aead = &pyconfig.aead;
        Hpke::new(mode.into(), kem.into(), kdf.into(), aead.into())
    }
}
