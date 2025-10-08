// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("Invalid JSON name `{0}`")]
    InvalidName(String),
    #[error("Invalid CBOR key `{0}`")]
    InvalidKey(i32),
    #[error("The verification key type is not compatible with the serialization format")]
    WrongVerificationKeyType,
    #[error("Trying to serialize an undefined verification key")]
    VerificationKeyUndefined,
    #[error("Validation error: {0}")]
    ValidationError(String),
}
