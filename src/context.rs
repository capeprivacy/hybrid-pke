use hpke_rs::Context as ContextRs;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::*;

pub(crate) type Context = ContextRs<HpkeRustCrypto>;

#[pyclass]
#[pyo3(name = "Context", module = "hybrid_pke")]
pub(crate) struct PyContext {
    ctx: Context,
}

impl PyContext {
    pub(crate) fn new(ctx: Context) -> Self {
        PyContext { ctx }
    }
}

#[pymethods]
impl PyContext {
    fn seal<'p>(
        &mut self,
        py: Python<'p>,
        aad: &PyBytes,
        plain_txt: &PyBytes,
    ) -> PyResult<&'p PyBytes> {
        let aad = aad.as_bytes();
        let plain_txt = plain_txt.as_bytes();
        let cipher_txt = self.ctx.seal(aad, plain_txt).map_err(handle_hpke_error)?;
        Ok(PyBytes::new(py, cipher_txt.as_slice()))
    }

    fn open<'p>(
        &mut self,
        py: Python<'p>,
        aad: &PyBytes,
        cipher_txt: &PyBytes,
    ) -> PyResult<&'p PyBytes> {
        let aad = aad.as_bytes();
        let cipher_txt = cipher_txt.as_bytes();
        let plain_txt = self.ctx.open(aad, cipher_txt).map_err(handle_hpke_error)?;
        Ok(PyBytes::new(py, plain_txt.as_slice()))
    }

    fn export<'p>(
        &self,
        py: Python<'p>,
        exporter_context: &PyBytes,
        length: usize,
    ) -> PyResult<&'p PyBytes> {
        let exporter_context = exporter_context.as_bytes();
        let exporter_secret = self
            .ctx
            .export(exporter_context, length)
            .map_err(handle_hpke_error)?;
        Ok(PyBytes::new(py, exporter_secret.as_slice()))
    }
}
