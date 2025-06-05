use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessengerError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Ephemeral key mismatch detected (possible MITM)")]
    EphemeralKeyMismatch,

    #[error("File integrity verification failed")]
    FileIntegrityMismatch,

    #[error("General error: {0}")]
    General(String),
}

impl From<anyhow::Error> for MessengerError {
    fn from(err: anyhow::Error) -> Self {
        MessengerError::General(err.to_string())
    }
}
