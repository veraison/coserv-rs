// SPDX-License-Identifier: Apache-2.0

//! Implementation of the CoSERV data model
//!
//! This module contains the implementation of the CoSERV data model
//! as defined in <https://datatracker.ietf.org/doc/draft-ietf-rats-coserv/02/>.
//!
//! Features include
//! - Representation of CoSERV
//! - Serialization to CBOR or base64 encoded CBOR
//! - Deserialization of CoSERV in CBOR or base64 encoded CBOR.
//!
//! CoSERV re-uses many definitions from CoRIM, hence these structures
//! are directly used from <https://github.com/veraison/corim-rs>.
//! For representing CMW CBOR reord, <https://github.com/veraison/rust-cmw>
//! is used.
//!
//! # Examples
//!
//! Create a CoSERV object and serialize to CBOR:
//!
//! ```rust
//!use coserv_rs::coserv::{
//!    ArtifactTypeChoice, Coserv, CoservBuilder, EnvironmentSelectorMap, Query, QueryBuilder,
//!    ResultTypeChoice, StatefulInstance, StatefulInstanceBuilder,
//!};
//!
//!use coserv_rs::coserv::corim_rs::{InstanceIdTypeChoice, ProfileTypeChoice};
//!
//!fn main() {
//!    // create list of stateful instances
//!    let instances: Vec<StatefulInstance> = vec![
//!        StatefulInstanceBuilder::new()
//!            .environment(InstanceIdTypeChoice::Bytes(
//!                [0x00_u8, 0x01, 0x02].as_slice().into(),
//!            ))
//!            .build()
//!            .unwrap(),
//!        StatefulInstanceBuilder::new()
//!            .environment(InstanceIdTypeChoice::Bytes(
//!                [0x01_u8, 0x02, 0x03].as_slice().into(),
//!            ))
//!            .build()
//!            .unwrap(),
//!    ];
//!
//!    // create query map
//!    let query = QueryBuilder::new()
//!        .artifact_type(ArtifactTypeChoice::ReferenceValues)
//!        .result_type(ResultTypeChoice::SourceArtifacts)
//!        .environment_selector(EnvironmentSelectorMap::Instance(instances))
//!        .build()
//!        .unwrap();
//!
//!    // create coserv map
//!    let coserv = CoservBuilder::new()
//!        .profile(ProfileTypeChoice::Uri("foo".into()))
//!        .query(query)
//!        .build()
//!        .unwrap();
//!
//!    let coserv_cbor = coserv.to_cbor().unwrap();
//!}
//!
//! ```
//!
//! Deserialize CBOR encoded CoSERV and generate response:
//!
//! ```rust
//!use coserv_rs::coserv::{Coserv, CoservBuilder, EnvironmentSelectorMap};
//!
//!use coserv_rs::coserv::{TimeDelta, TimeStamp};
//!
//!use coserv_rs::coserv::{
//!    CoservResultBuilder, ReferenceValuesQuad, ReferenceValuesQuadBuilder, ReferenceValuesResult,
//!    ResultSetTypeChoice,
//!};
//!
//!use coserv_rs::coserv::corim_rs::{
//!    CryptoKeyTypeChoice, EnvironmentMap, MeasurementMap, MeasurementValuesMapBuilder,
//!    ReferenceTripleRecord,
//!};
//!
//!fn main() {
//!    let cbor_data: Vec<u8> = vec![
//!        0xA2, 0x00, 0xD8, 0x20, 0x63, 0x66, 0x6F, 0x6F, 0x01, 0xA4, 0x00, 0x02, 0x01, 0xA1, 0x01,
//!        0x82, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x01,
//!        0x02, 0x03, 0x02, 0xC0, 0x78, 0x19, 0x32, 0x30, 0x32, 0x35, 0x2D, 0x31, 0x30, 0x2D, 0x32,
//!        0x37, 0x54, 0x31, 0x39, 0x3A, 0x31, 0x31, 0x3A, 0x33, 0x30, 0x2B, 0x30, 0x35, 0x3A, 0x33,
//!        0x30, 0x03, 0x01,
//!    ];
//!
//!    let de_coserv = Coserv::from_cbor(cbor_data.as_slice()).unwrap();
//!    // check artifact type and result type, then direct to
//!    // the correct handler
//!
//!    // check environment selector type, then direct to
//!    // the correct handler
//!    let mut rv_quads: Vec<ReferenceValuesQuad> = vec![];
//!
//!    match de_coserv.query.environment_selector {
//!        EnvironmentSelectorMap::Instance(ref v) => {
//!            for si in v.iter() {
//!                let mut ref_env = EnvironmentMap::default();
//!                ref_env.instance = Some(si.environment.clone());
//!
//!                // gather measurements for the environment
//!                let mval_map = MeasurementValuesMapBuilder::new()
//!                    .name("foo".into())
//!                    .build()
//!                    .unwrap();
//!                let mut meas_map = MeasurementMap::default();
//!                meas_map.mval = mval_map;
//!                let rv_triple = ReferenceTripleRecord {
//!                    ref_env: ref_env,
//!                    ref_claims: vec![meas_map],
//!                };
//!                let rv_quad = ReferenceValuesQuadBuilder::new()
//!                    .triple(rv_triple)
//!                    .authorities(vec![CryptoKeyTypeChoice::Bytes(
//!                        [0x00_u8, 0x01].as_slice().into(),
//!                    )])
//!                    .build()
//!                    .unwrap();
//!                rv_quads.push(rv_quad);
//!            }
//!        }
//!        _ => panic!(),
//!    }
//!
//!    let ref_vals_results = ReferenceValuesResult { rv_quads: rv_quads };
//!
//!    // build result set
//!    let results = CoservResultBuilder::new()
//!        .expiry(TimeStamp::now().add(TimeDelta::days(10)))
//!        .result_set(ResultSetTypeChoice::ReferenceValues(ref_vals_results))
//!        .build()
//!        .unwrap();
//!
//!    // build response
//!    let response = CoservBuilder::new()
//!        .profile(de_coserv.profile)
//!        .query(de_coserv.query)
//!        .results(results)
//!        .build()
//!        .unwrap();
//!
//!    // serialize to cbor
//!    let response_cbor = response.to_cbor().unwrap();
//!}
//! ```

use crate::error::CoservError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use corim_rs::corim::ProfileTypeChoice;
use serde::{
    de::{self, Deserialize, Deserializer, Error, MapAccess, Visitor},
    ser::{Serialize, SerializeMap, Serializer},
};
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;

// Contains structures used by both query and result
mod common;

// data types used in CoSERV query
mod query;

// data types used in CoSERV response
mod result;

// re-export to simplify the API
pub use common::*;
pub use query::*;
pub use result::*;

pub use corim_rs;

pub use cmw;

/// Represents a CoSERV object
#[derive(Debug, PartialEq)]
pub struct Coserv<'a> {
    /// CoSERV profile
    pub profile: ProfileTypeChoice<'a>,
    /// CoSERV query map
    pub query: Query<'a>,
    /// optional CoSERV result map
    pub results: Option<CoservResult<'a>>,
}

impl<'a> Coserv<'a> {
    /// Marshal CoSERV object to CBOR
    /// deterministically encoded: <https://www.rfc-editor.org/rfc/rfc8949#section-4.2>
    pub fn to_cbor(&self) -> Result<Vec<u8>, CoservError> {
        let mut buf = Vec::<u8>::new();
        ciborium::into_writer(&self, &mut buf).map_err(CoservError::custom)?;
        Ok(buf)
    }

    /// Unmarshal CBOR into CoSERV object
    pub fn from_cbor<R: Read>(src: R) -> Result<Self, CoservError> {
        ciborium::from_reader(src).map_err(CoservError::custom)
    }

    /// Generate URL safe base64 encoding of the CBOR encoded CoSERV oject
    pub fn to_b64_url(&self) -> Result<String, CoservError> {
        let cbor = self.to_cbor()?;
        let b64 = URL_SAFE_NO_PAD.encode(cbor.as_slice());
        Ok(b64)
    }

    /// Create CoSERV object from URL safe base64 encoded CBOR CoSERV
    pub fn from_b64_url(b64: &[u8]) -> Result<Self, CoservError> {
        let cbor = URL_SAFE_NO_PAD.decode(b64).map_err(CoservError::custom)?;
        Self::from_cbor(cbor.as_slice())
    }
}

/// Builder for CoSERV object
#[derive(Debug, Default)]
pub struct CoservBuilder<'a> {
    pub profile: Option<ProfileTypeChoice<'a>>,
    pub query: Option<Query<'a>>,
    pub results: Option<CoservResult<'a>>,
}

impl<'a> CoservBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the profile
    pub fn profile(mut self, value: ProfileTypeChoice<'a>) -> Self {
        self.profile = Some(value);
        self
    }

    /// Set the query
    pub fn query(mut self, value: Query<'a>) -> Self {
        self.query = Some(value);
        self
    }

    /// Set the results
    pub fn results(mut self, value: CoservResult<'a>) -> Self {
        self.results = Some(value);
        self
    }

    /// Method to build the CoSERV object from the builder
    pub fn build(self) -> Result<Coserv<'a>, CoservError> {
        // TODO: check if query artifact type and result type
        // matches those present in result
        Ok(Coserv {
            profile: self.profile.ok_or(CoservError::RequiredFieldNotSet(
                "profile".into(),
                "coserv".into(),
            ))?,
            query: self.query.ok_or(CoservError::RequiredFieldNotSet(
                "query".into(),
                "coserv".into(),
            ))?,
            results: self.results,
        })
    }
}

impl Serialize for Coserv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num_elts = 2 + self.results.is_some() as usize;
        let mut map = serializer.serialize_map(Some(num_elts))?;
        map.serialize_entry(&0, &self.profile)?;
        map.serialize_entry(&1, &self.query)?;
        if let Some(res) = &self.results {
            map.serialize_entry(&2, res)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Coserv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoservVisitor<'a> {
            marker: PhantomData<&'a str>,
        }
        impl<'de, 'a> Visitor<'de> for CoservVisitor<'a> {
            type Value = Coserv<'a>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "map containing CoSERV fields")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut builder = CoservBuilder::new();
                loop {
                    match access.next_key::<i64>()? {
                        Some(0) => {
                            builder = builder.profile(access.next_value::<ProfileTypeChoice>()?);
                        }
                        Some(1) => {
                            builder = builder.query(access.next_value::<Query>()?);
                        }
                        Some(2) => {
                            builder = builder.results(access.next_value::<CoservResult>()?);
                        }
                        Some(n) => {
                            return Err(de::Error::unknown_field(
                                n.to_string().as_str(),
                                &["0", "1", "2"],
                            ));
                        }
                        None => break,
                    };
                }
                builder.build().map_err(M::Error::custom)
            }
        }
        deserializer.deserialize_map(CoservVisitor {
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_valid_cbor() {
        let tests = [
            "example-class-selector-noindent",
            "example-class-selector",
            "example-group-selector",
            "example-instance-selector",
            "rv-class-simple-results-source-artifacts",
            "rv-class-simple-results",
            "rv-class-simple",
            "rv-class-stateful",
            "rv-results",
        ];

        let mut path = PathBuf::from("testdata");

        for case in tests.iter() {
            path.push(case);
            path.set_extension("cbor");
            let cbor = fs::read(&path).unwrap();
            let coserv = Coserv::from_cbor(cbor.as_slice()).unwrap();
            let cbor_ser = coserv.to_cbor().unwrap();
            assert_eq!(cbor_ser, cbor);
            path.pop();
        }
    }

    #[test]
    fn test_valid_b64() {
        let tests = [
            "example-class-selector-noindent",
            "example-class-selector",
            "example-group-selector",
            "example-instance-selector",
            "rv-class-simple-results-source-artifacts",
            "rv-class-simple-results",
            "rv-class-simple",
            "rv-class-stateful",
            "rv-results",
        ];

        let mut path = PathBuf::from("testdata");

        for case in tests.iter() {
            path.push(case);
            path.set_extension("b64u");
            let b64u = fs::read(&path).unwrap();
            let coserv = Coserv::from_b64_url(b64u.as_slice()).unwrap();
            let b64u_ser = coserv.to_b64_url().unwrap();
            assert_eq!(Vec::<u8>::from(b64u_ser.as_bytes()), b64u);
            path.pop();
        }
    }

    #[test]
    fn test_builder() {
        let builder = CoservBuilder::new();
        assert!(builder.build().is_err());

        let mut builder = CoservBuilder::new();
        builder = builder.profile(ProfileTypeChoice::Uri("foo".into()));
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid() {
        let cbor: Vec<u8> = vec![0xa1, 0x04, 0x01];
        let err: Result<Coserv, _> = ciborium::from_reader(cbor.as_slice());
        assert!(err.is_err());
    }
}
