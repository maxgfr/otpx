//! otpx core: everything the CLI and the web app share.
//!
//! OTP codes ([`otp`]), `otpauth://` URIs ([`uri`]), the account model ([`model`]), the
//! encrypted vault ([`vault`]), conflict-free merging ([`merge`]), import/export
//! ([`formats`]), QR codes ([`qr`]) and sharing ([`share`]). Pure Rust, no I/O: the same
//! code runs natively and in the browser (wasm32).

pub mod b32;
pub mod crypto;
pub mod error;
pub mod formats;
pub mod merge;
pub mod model;
pub mod otp;
pub mod qr;
pub mod share;
pub mod uri;
pub mod vault;

pub use error::{Error, Result};
pub use model::{Entry, Kind, VaultData};
pub use otp::Algorithm;
