// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

mod discovery;

pub use discovery::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Discovery(DiscoveryError),
    #[error("Unclassified CoSERV error.")]
    Unknown,
}
