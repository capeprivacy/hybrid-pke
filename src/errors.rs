use hpke_rs::HpkeError;
use pyo3::exceptions::PyException;
use pyo3::{create_exception, PyErr};

create_exception!(
    errors,
    OpenError,
    PyException,
    "Error opening an HPKE ciphertext."
);
create_exception!(
    errors,
    InvalidConfig,
    PyException,
    "Invalid HPKE configuration or arguments."
);
create_exception!(errors, InvalidInput, PyException, "Invalid input.");
create_exception!(errors, UnknownMode, PyException, "Unknown HPKE mode.");
create_exception!(
    errors,
    InconsistentPsk,
    PyException,
    "Inconsistent PSK input."
);
create_exception!(
    errors,
    MissingPsk,
    PyException,
    "PSK input is required but missing."
);
create_exception!(
    errors,
    UnnecessaryPsk,
    PyException,
    "PSK input is provided but not needed."
);
create_exception!(
    errors,
    InsecurePsk,
    PyException,
    "PSK input is too short (needs to be at least 32 bytes)."
);
create_exception!(
    errors,
    CryptoError,
    PyException,
    "An error in the crypto library occurred."
);
create_exception!(
    errors,
    MessageLimitReached,
    PyException,
    "The message limit for this AEAD, key, and nonce."
);
create_exception!(
    errors,
    InsufficientRandomness,
    PyException,
    "Unable to collect enough randomness."
);

#[inline(always)]
pub(crate) fn handle_hpke_error(e: HpkeError) -> PyErr {
    match e {
        HpkeError::OpenError => OpenError::new_err("Error opening an HPKE ciphertext."),
        HpkeError::InvalidConfig => {
            InvalidConfig::new_err("Invalid HPKE configuration or arguments.")
        }
        HpkeError::InvalidInput => InvalidInput::new_err("Invalid input."),
        HpkeError::UnknownMode => UnknownMode::new_err("Unknown HPKE mode."),
        HpkeError::InconsistentPsk => InconsistentPsk::new_err("Inconsistent PSK input."),
        HpkeError::MissingPsk => MissingPsk::new_err("PSK input is required but missing."),
        HpkeError::UnnecessaryPsk => {
            UnnecessaryPsk::new_err("PSK input is provided but not needed.")
        }
        HpkeError::InsecurePsk => {
            InsecurePsk::new_err("PSK input is too short (needs to be at least 32 bytes).")
        }
        HpkeError::CryptoError(s) => CryptoError::new_err(s),
        HpkeError::MessageLimitReached => {
            MessageLimitReached::new_err("Hit the message limit for this AEAD, key, and nonce.")
        }
        HpkeError::InsufficientRandomness => {
            InsufficientRandomness::new_err("Unable to collect enough randomness.")
        }
    }
}
