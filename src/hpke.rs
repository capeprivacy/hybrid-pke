use hpke_rs::HpkePrivateKey;
use hpke_rs::{Hpke as HpkeRs, HpkePublicKey};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::config::*;
use crate::errors::*;

pub(crate) type Hpke = HpkeRs<HpkeRustCrypto>;

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

    fn generate_key_pair<'p>(&self, py: Python<'p>) -> PyResult<(&'p PyBytes, &'p PyBytes)> {
        let cfg: Hpke = self.into();
        let keypair = cfg
            .generate_key_pair()
            .map_err(|hpke_error| handle_hpke_error(hpke_error))?;
        let (sk, pk) = keypair.into_keys();
        let sk_py = PyBytes::new(py, sk.as_slice());
        let pk_py = PyBytes::new(py, pk.as_slice());
        Ok((sk_py, pk_py))
    }

    #[args(
        psk = "None",
        psk_id = "None",
        sk_s = "None",
    )]
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

        // convert all args and drop py refs immediately
        let pk_r = HpkePublicKey::new(pk_r.as_bytes().into());
        let info = info.as_bytes();
        let aad = aad.as_bytes();
        let plain_txt = plain_txt.as_bytes();
        let psk = psk.and_then(|x| Some(x.as_bytes()));
        let psk_id = psk_id.and_then(|x| Some(x.as_bytes()));

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
        .map_err(|hpke_error| handle_hpke_error(hpke_error))?;

        // convert return vals back to PyBytes
        let encap_py = PyBytes::new(py, encap.as_slice());
        let cipher_txt_py = PyBytes::new(py, cipher_txt.as_slice());
        Ok((encap_py, cipher_txt_py))
    }

    #[args(
        psk = "None",
        psk_id = "None",
        pk_s = "None"
    )]
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

        // convert all args and drop py refs immediately
        let enc = enc.as_bytes();
        let sk_r = HpkePrivateKey::new(sk_r.as_bytes().into());
        let info = info.as_bytes();
        let aad = aad.as_bytes();
        let cipher_txt = cipher_txt.as_bytes();
        let psk = psk.and_then(|x| Some(x.as_bytes()));
        let psk_id = psk_id.and_then(|x| Some(x.as_bytes()));

        // perform single-shot open
        let plain_txt = match pk_s {
            None => cfg.open(enc, &sk_r, info, aad, cipher_txt, psk, psk_id, None),
            // TODO(jason) would be great if we could go from &[u8] to &HpkePublicKey here
            Some(pk) => {
                let pk = HpkePublicKey::new(pk.as_bytes().into());
                cfg.open(enc, &sk_r, info, aad, cipher_txt, psk, psk_id, Some(&pk))
            }
        }
        .map_err(|hpke_error| handle_hpke_error(hpke_error))?;

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
