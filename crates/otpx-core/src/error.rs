//! Errors of the core.

/// Result alias of the core.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What can go wrong in the core. Messages are meant for the user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A secret that is not valid base32 (or empty).
    #[error("invalid secret: {0}")]
    Secret(String),
    /// A malformed `otpauth://` or `otpauth-migration://` URI.
    #[error("invalid URI: {0}")]
    Uri(String),
    /// An entry field out of range.
    #[error("invalid entry: {0}")]
    Entry(String),
    /// A file that does not match the format it claims (or any known format).
    #[error("unreadable {format} data: {reason}")]
    Format {
        /// Format name.
        format: &'static str,
        /// What did not parse.
        reason: String,
    },
    /// The data is encrypted and needs a password.
    #[error("this {0} file is encrypted: a password is needed")]
    NeedsPassword(&'static str),
    /// Wrong password, wrong key or tampered ciphertext.
    #[error("wrong password or key, or the data was modified")]
    Decrypt,
    /// The system random source failed.
    #[error("system random source unavailable")]
    Random,
    /// A share link past its expiry.
    #[error("this share expired")]
    Expired,
    /// A feature this build lacks.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// QR code encoding or decoding failed.
    #[error("QR code: {0}")]
    Qr(String),
}

impl Error {
    pub(crate) fn format(format: &'static str, reason: impl std::fmt::Display) -> Error {
        Error::Format {
            format,
            reason: reason.to_string(),
        }
    }
}
