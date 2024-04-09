use hpke_rs::HpkePrivateKey;
use hpke_rs::{Hpke as HpkeRs, HpkePublicKey};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};

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
    #[pyo3(get)]
    mode: PyMode,
    #[pyo3(get)]
    kem: PyKemAlgorithm,
    #[pyo3(get)]
    kdf: PyKdfAlgorithm,
    #[pyo3(get)]
    aead: PyAeadAlgorithm,
    hpke: Hpke,
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
        let hpke = Hpke::new((&mode).into(), (&kem).into(), (&kdf).into(), (&aead).into());
        PyHpke {
            mode,
            kem,
            kdf,
            aead,
            hpke,
        }
    }

    pub fn __deepcopy__(&self, _memo: &PyAny) -> Self {
        self.clone()
    }

    /// Set up an HPKE sender context
    #[args(psk = "None", psk_id = "None", sk_s = "None")]
    fn setup_sender<'p>(
        &mut self,
        py: Python<'p>,
        pk_r: &PyBytes,
        info: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        sk_s: Option<&PyBytes>,
    ) -> PyResult<(&'p PyBytes, PyContext)> {
        let cfg = &mut self.hpke;

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
        let cfg = &self.hpke;

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
        &mut self,
        py: Python<'p>,
        pk_r: &PyBytes,
        info: &PyBytes,
        aad: &PyBytes,
        plain_txt: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        sk_s: Option<&PyBytes>,
    ) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg = &mut self.hpke;

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
        let cfg = &self.hpke;

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
        Ok(PyBytes::new(py, plain_txt.as_slice()))
    }

    /// Derive an exporter secret for sender with public key `pk_r`, single-shot
    #[allow(clippy::too_many_arguments)]
    #[args(psk = "None", psk_id = "None", sk_s = "None")]
    fn send_export<'p>(
        &mut self,
        py: Python<'p>,
        pk_r: &PyBytes,
        info: &PyBytes,
        exporter_context: &PyBytes,
        length: usize,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        sk_s: Option<&PyBytes>,
    ) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg = &mut self.hpke;

        // convert args, drop py refs
        let pk_r = HpkePublicKey::new(pk_r.as_bytes().into());
        let info = info.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());
        let exporter_context = exporter_context.as_bytes();

        // derive sender export secret
        let (encap, exporter_secret) = match sk_s {
            None => cfg.send_export(&pk_r, info, psk, psk_id, None, exporter_context, length),
            Some(sk) => {
                let sk = HpkePrivateKey::new(sk.as_bytes().into());
                cfg.send_export(
                    &pk_r,
                    info,
                    psk,
                    psk_id,
                    Some(&sk),
                    exporter_context,
                    length,
                )
            }
        }
        .map_err(handle_hpke_error)?;

        // convert return vals back to PyBytes
        let encap_py = PyBytes::new(py, encap.as_slice());
        let exporter_secret_py = PyBytes::new(py, exporter_secret.as_slice());
        Ok((encap_py, exporter_secret_py))
    }

    /// Derive an exporter secret for receiver with private key `sk_r`, single-shot
    #[allow(clippy::too_many_arguments)]
    #[args(psk = "None", psk_id = "None", pk_s = "None")]
    fn receiver_export<'p>(
        &self,
        py: Python<'p>,
        enc: &PyBytes,
        sk_r: &PyBytes,
        info: &PyBytes,
        exporter_context: &PyBytes,
        length: usize,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
        pk_s: Option<&PyBytes>,
    ) -> PyResult<&'p PyBytes> {
        let cfg = &self.hpke;

        // convert all args and drop py refs immediately
        let enc = enc.as_bytes();
        let sk_r = HpkePrivateKey::new(sk_r.as_bytes().into());
        let info = info.as_bytes();
        let exporter_context = exporter_context.as_bytes();
        let psk = psk.map(|x| x.as_bytes());
        let psk_id = psk_id.map(|x| x.as_bytes());

        // derive receiver export secret
        let exporter_secret = match pk_s {
            None => cfg.receiver_export(
                enc,
                &sk_r,
                info,
                psk,
                psk_id,
                None,
                exporter_context,
                length,
            ),
            Some(pk) => {
                let pk = HpkePublicKey::new(pk.as_bytes().into());
                cfg.receiver_export(
                    enc,
                    &sk_r,
                    info,
                    psk,
                    psk_id,
                    Some(&pk),
                    exporter_context,
                    length,
                )
            }
        }
        .map_err(handle_hpke_error)?;

        Ok(PyBytes::new(py, exporter_secret.as_slice()))
    }

    /// Create an encryption context from a shared secret
    #[args(psk = "None", psk_id = "None")]
    fn key_schedule(
        &self,
        shared_secret: &PyBytes,
        info: &PyBytes,
        psk: Option<&PyBytes>,
        psk_id: Option<&PyBytes>,
    ) -> PyResult<PyContext> {
        let no_psk = psk.is_none() & psk_id.is_none();
        let both_psk = psk.is_some() & psk_id.is_some();
        if !(no_psk | both_psk) {
            return Err(PyValueError::new_err(
                format!("`psk` and `psk_id` must appear together or not at all. Found: psk={psk:?} and psk_id={psk_id:?}.")
            ));
        }

        let cfg = &self.hpke;
        let shared_secret = shared_secret.as_bytes();
        let info = info.as_bytes();
        let psk: &[u8] = psk.map_or(&[], |x| x.as_bytes());
        let psk_id: &[u8] = psk_id.map_or(&[], |x| x.as_bytes());
        let context = cfg
            .key_schedule(shared_secret, info, psk, psk_id)
            .map_err(handle_hpke_error)?;
        Ok(PyContext::new(context))
    }

    /// Generate a key-pair according to the KemAlgorithm in this Hpke config
    fn generate_key_pair<'p>(&mut self, py: Python<'p>) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg = &mut self.hpke;
        let keypair = cfg.generate_key_pair().map_err(handle_hpke_error)?;
        let (sk, pk) = keypair.into_keys();
        let sk_py = PyBytes::new(py, sk.as_slice());
        let pk_py = PyBytes::new(py, pk.as_slice());
        Ok((sk_py, pk_py))
    }

    /// Derive a key-pair from given randomness according to the KemAlgorithm in this Hpke config
    fn derive_key_pair<'p>(
        &self,
        py: Python<'p>,
        ikm: &PyBytes,
    ) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg = &self.hpke;
        let ikm = ikm.as_bytes();
        let keypair = cfg.derive_key_pair(ikm).map_err(handle_hpke_error)?;
        let (sk, pk) = keypair.into_keys();
        let sk_py = PyBytes::new(py, sk.as_slice());
        let pk_py = PyBytes::new(py, pk.as_slice());
        Ok((sk_py, pk_py))
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
