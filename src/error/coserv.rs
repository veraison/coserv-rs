// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoservError {
    #[error("CoSERV result is invalid because: {0}")]
    InvalidResult(String),
    #[error("Required field {0} not set in {1}")]
    RequiredFieldNotSet(String, String),
    #[error("Cannot add {0} to result set of type {1}")]
    SetQuadsFailed(String, String),
    #[error("CoSERV error: {0}")]
    Custom(String),
}

impl CoservError {
    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        Self::Custom(message.to_string())
    }
}
