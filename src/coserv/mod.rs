// SPDX-License-Identifier: Apache-2.0

//! Implementation of the CoSERV data model
//!
//! This module contains the implementation of the CoSERV data model
//! as defined in <https://datatracker.ietf.org/doc/draft-ietf-rats-coserv/06/>.
//!
//! Features include
//! - Representation of CoSERV
//! - Serialization to CBOR or base64 encoded CBOR
//! - Deserialization of CoSERV in CBOR or base64 encoded CBOR.
//! - Signing of CoSERV objects.
//! - Verification of signed CoSERV.
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
//!    ArtifactTypeChoice, CoservBuilder, CoservEnvQueryBuilder, CoservProfile,
//!    EnvironmentSelectorMap, ResultTypeChoice, StatefulInstance, StatefulInstanceBuilder,
//!};
//!
//!use coserv_rs::coserv::corim_rs::InstanceIdTypeChoice;
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
//!    let query = CoservEnvQueryBuilder::new()
//!        .artifact_type(ArtifactTypeChoice::ReferenceValues)
//!        .result_type(ResultTypeChoice::SourceArtifacts)
//!        .environment_selector(EnvironmentSelectorMap::Instance(instances))
//!        .build()
//!        .unwrap();
//!
//!    // create coserv map
//!    let coserv = CoservBuilder::new()
//!        .profile(CoservProfile::Uri("foo".into()))
//!        .query(query.into())
//!        .build()
//!        .unwrap();
//!
//!    let coserv_cbor = coserv.to_cbor().unwrap();
//!}
//! ```
//!
//! Deserialize CBOR encoded CoSERV and generate response:
//!
//! ```rust
//!use coserv_rs::coserv::{Coserv, CoservBuilder, CoservQuery, EnvironmentSelectorMap};
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
//!        0xA2, 0x00, 0x63, 0x66, 0x6F, 0x6F, 0x01, 0xA3, 0x00, 0x02, 0x01, 0xA1, 0x01, 0x82, 0x81,
//!        0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03,
//!        0x02, 0x00
//!    ];
//!
//!    let de_coserv = Coserv::from_cbor(cbor_data.as_slice()).unwrap();
//!
//!    let mut rv_quads: Vec<ReferenceValuesQuad> = vec![];
//!
//!    // check the query type
//!    let CoservQuery::EnvQuery(ref env_query) = de_coserv.query else {
//!        panic!()
//!    };
//!
//!    // check the environent selector type
//!    match env_query.environment_selector {
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
//!                    ref_env,
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
//!    let ref_vals_results = ReferenceValuesResult { rv_quads };
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
//!
//! Signing CoSERV using a user defined signer
//!
//! ```rust
//!use corim_rs::CorimError;
//!use coserv_rs::coserv::{CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner, CoseVerifier, Coserv};
//!
//!struct FakeSigner {}
//!
//!impl CoseKeyOwner for FakeSigner {
//!    fn to_cose_key(&self) -> CoseKey {
//!        CoseKey::default()
//!    }
//!}
//!
//!impl CoseSigner for FakeSigner {
//!    // implement signing
//!    fn sign(&self, _alg: CoseAlgorithm, _data: &[u8]) -> Result<Vec<u8>, CorimError> {
//!        Ok(vec![0x01, 0x02, 0x03])
//!    }
//!}
//!
//!impl CoseVerifier for FakeSigner {
//!    // implement verification
//!    fn verify_signature(
//!        &self,
//!        _alg: CoseAlgorithm,
//!        _sig: &[u8],
//!        _data: &[u8],
//!    ) -> Result<(), CorimError> {
//!        Ok(())
//!    }
//!}
//!
//!fn main() {
//!    let coserv_response_cbor: Vec<u8> = vec![
//!        0xA3, 0x00, 0x63, 0x66, 0x6F, 0x6F, 0x01, 0xA3, 0x00, 0x02, 0x01, 0xA1, 0x01, 0x82, 0x81,
//!        0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03,
//!        0x02, 0x00, 0x02, 0xA2, 0x00, 0x81, 0xA2, 0x01, 0x81, 0xD9, 0x02, 0x30, 0x42, 0x00, 0x01,
//!        0x02, 0x82, 0xA1, 0x01, 0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xA1, 0x01, 0xA1,
//!        0x0B, 0x63, 0x66, 0x6F, 0x6F, 0x0A, 0xC0, 0x78, 0x19, 0x32, 0x30, 0x32, 0x35, 0x2D, 0x31,
//!        0x31, 0x2D, 0x32, 0x31, 0x54, 0x31, 0x36, 0x3A, 0x30, 0x38, 0x3A, 0x35, 0x36, 0x2B, 0x30,
//!        0x35, 0x3A, 0x33, 0x30,
//!    ];
//!
//!    // construct response like in previous example
//!    let response = Coserv::from_cbor(coserv_response_cbor.as_slice()).unwrap();
//!
//!    let signer = FakeSigner {};
//!    let signed_response = response.sign(&signer, CoseAlgorithm::ES256).unwrap();
//!
//!    let verifier = FakeSigner {};
//!    let coserv = Coserv::verify_and_extract(&verifier, signed_response.as_slice()).unwrap();
//!}
//! ```
//!
//! By enabling the `openssl` feature, and implementation of
//! `CoseSigner` and `CoseVerifier` using openssl becomes available.
//! These are implemented by enabling `openssl` feature on corim-rs.
//!
//! ```ignore
//!// enable `openssl' feature for an implementation of
//!// CoseSigner and CoseVerifier using openssl
//!use coserv_rs::coserv::{CoseAlgorithm, Coserv, OpensslSigner, OpensslVerifier};
//!
//!fn main() {
//!    let coserv_response_cbor: Vec<u8> = vec![
//!        0xA3, 0x00, 0x63, 0x66, 0x6F, 0x6F, 0x01, 0xA3, 0x00, 0x02, 0x01, 0xA1, 0x01, 0x82, 0x81,
//!        0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03,
//!        0x02, 0x00, 0x02, 0xA2, 0x00, 0x81, 0xA2, 0x01, 0x81, 0xD9, 0x02, 0x30, 0x42, 0x00, 0x01,
//!        0x02, 0x82, 0xA1, 0x01, 0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xA1, 0x01, 0xA1,
//!        0x0B, 0x63, 0x66, 0x6F, 0x6F, 0x0A, 0xC0, 0x78, 0x19, 0x32, 0x30, 0x32, 0x35, 0x2D, 0x31,
//!        0x31, 0x2D, 0x32, 0x31, 0x54, 0x31, 0x36, 0x3A, 0x30, 0x38, 0x3A, 0x35, 0x36, 0x2B, 0x30,
//!        0x35, 0x3A, 0x33, 0x30,
//!    ];
//!
//!    let priv_pem = r#"
//!-----BEGIN EC PRIVATE KEY-----
//!MHcCAQEEIGcXyKllYJ/Ll0jUI9LfK/7uokvFibisW5lM8DZaRO+toAoGCCqGSM49
//!AwEHoUQDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpoeCJsPxG2h
//!zMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
//!-----END EC PRIVATE KEY-----
//!"#;
//!    let pub_pem = r#"
//!-----BEGIN PUBLIC KEY-----
//!MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/gPssLIiLnF0XrTGU73XMKlTIk4Q
//!hU80ttXzJ7waTpoeCJsPxG2hzMuUkHMOLrZxNpwxH004vyaHpF9TYTeXCQ==
//!-----END PUBLIC KEY-----
//!"#;
//!
//!    // construct response like in previous example
//!    let response = Coserv::from_cbor(coserv_response_cbor.as_slice()).unwrap();
//!
//!    // on the sender side
//!    // sign the response
//!    let signer = OpensslSigner::from_pem(priv_pem).unwrap();
//!    let signed_response = response.sign(&signer, CoseAlgorithm::ES256).unwrap();
//!
//!    // on the receiver side:
//!    // verify signature and extracting coserv
//!    let verifier = OpensslVerifier::from_pem(pub_pem).unwrap();
//!    let coserv = Coserv::verify_and_extract(&verifier, signed_response.as_slice()).unwrap();
//!}
//! ```
//!
//! Using JWK
//!
//! ```ignore
//!// enable `openssl' feature for an implementation of
//!// CoseSigner and CoseVerifier using openssl
//!use coserv_rs::coserv::{CoseAlgorithm, Coserv, OpensslSigner, OpensslVerifier};
//!
//!fn main() {
//!    let coserv_response_cbor: Vec<u8> = vec![
//!        0xA3, 0x00, 0x63, 0x66, 0x6F, 0x6F, 0x01, 0xA3, 0x00, 0x02, 0x01, 0xA1, 0x01, 0x82, 0x81,
//!        0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xD9, 0x02, 0x30, 0x43, 0x01, 0x02, 0x03,
//!        0x02, 0x00, 0x02, 0xA2, 0x00, 0x81, 0xA2, 0x01, 0x81, 0xD9, 0x02, 0x30, 0x42, 0x00, 0x01,
//!        0x02, 0x82, 0xA1, 0x01, 0xD9, 0x02, 0x30, 0x43, 0x00, 0x01, 0x02, 0x81, 0xA1, 0x01, 0xA1,
//!        0x0B, 0x63, 0x66, 0x6F, 0x6F, 0x0A, 0xC0, 0x78, 0x19, 0x32, 0x30, 0x32, 0x35, 0x2D, 0x31,
//!        0x31, 0x2D, 0x32, 0x31, 0x54, 0x31, 0x36, 0x3A, 0x30, 0x38, 0x3A, 0x35, 0x36, 0x2B, 0x30,
//!        0x35, 0x3A, 0x33, 0x30,
//!    ];
//!
//!    let priv_jwk = r#"
//!{
//!  "kty": "EC",
//!  "crv": "P-256",
//!  "alg": "ES256",
//!  "d": "ZxfIqWVgn8uXSNQj0t8r_u6iS8WJuKxbmUzwNlpE760",
//!  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
//!  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
//!}
//!"#;
//!    let pub_jwk = r#"
//!{
//!  "kty": "EC",
//!  "crv": "P-256",
//!  "alg": "ES256",
//!  "x": "_gPssLIiLnF0XrTGU73XMKlTIk4QhU80ttXzJ7waTpo",
//!  "y": "HgibD8RtoczLlJBzDi62cTacMR9NOL8mh6RfU2E3lwk"
//!}
//!"#;
//!
//!    // construct response like in previous example
//!    let response = Coserv::from_cbor(coserv_response_cbor.as_slice()).unwrap();
//!
//!    // on the sender side:
//!    // sign the response
//!    let signer = OpensslSigner::from_jwk(priv_jwk).unwrap();
//!    let signed_response = response.sign(&signer, CoseAlgorithm::ES384).unwrap();
//!
//!    // on the receiver side:
//!    // verify signature and extracting coserv
//!    let verifier = OpensslVerifier::from_jwk(pub_jwk).unwrap();
//!    let coserv = Coserv::verify_and_extract(&verifier, signed_response.as_slice()).unwrap();
//!}

use crate::error::CoservError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{
    de::{self, Deserialize, Deserializer, Error, MapAccess, Visitor},
    ser::{Serialize, SerializeMap, Serializer},
};
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;

use coset::iana::EnumI64;
use coset::{
    AsCborValue, ContentType, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable,
};

// Contains structures used by both query and result
mod common;

// data types used in CoSERV query
mod query;

// data types used in CoSERV response
mod result;

// for signing and verification of CoSERV
#[cfg(feature = "openssl")]
mod openssl;

// re-export to simplify the API
pub use common::*;
#[cfg(feature = "openssl")]
pub use openssl::*;
pub use query::*;
pub use result::*;

pub use corim_rs;

/// Representation of OID.
/// Use [ObjectIdentifier::try_from<&Vec<u8>>] to construct from BER encoding
/// or [ObjectIdentifier::try_from<&str>] to construct from dot decimal form.
pub use corim_rs::ObjectIdentifier;

pub use cmw;

pub use corim_rs::{CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner, CoseVerifier};

/// Represents a CoSERV object
#[derive(Debug, PartialEq)]
pub struct Coserv<'a> {
    /// CoSERV profile
    pub profile: CoservProfile,
    /// CoSERV query map
    pub query: CoservQuery<'a>,
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

    /// Signs and serializes CoSERV object to CBOR. Signed CoSERV is
    /// a COSE_Sign1 object with tag 18, carrying CBOR encoded CoSERV payloadwith.
    pub fn sign(
        &self,
        signer: &impl CoseSigner,
        cose_alg: CoseAlgorithm,
    ) -> Result<Vec<u8>, CoservError> {
        let aad: &[u8] = &[];
        let payload = self.to_cbor()?;
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::from_i64(cose_alg.into()).ok_or(
                CoservError::SigningError(CoservError::UnknownAlgorithm(cose_alg.into()).into()),
            )?)
            .content_type("application/coserv+cbor".to_string())
            .build();

        let sign1_value = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(aad, |pt| signer.sign(cose_alg, pt))
            .map_err(|e| CoservError::SigningError(e.into()))?
            .build()
            .to_cbor_value()
            .map_err(|e| CoservError::SigningError(e.into()))?;

        let tagged_sign1_value = ciborium::value::Value::Tag(18, Box::new(sign1_value));
        let mut buff: Vec<u8> = vec![];

        ciborium::into_writer(&tagged_sign1_value, &mut buff).map_err(CoservError::custom)?;
        Ok(buff)
    }

    /// Verifies the signature on the serialized signed CoSERV data
    /// and creates a CoSERV object by deserializing the payload.
    pub fn verify_and_extract(
        verifier: &impl CoseVerifier,
        data: &[u8],
    ) -> Result<Self, CoservError> {
        let sign1 = CoseSign1::from_tagged_slice(data).map_err(CoservError::custom)?;

        // TODO: ContentType::Assigned variant, when CoAP
        // content format id gets assigned
        if let Some(ContentType::Text(ref cty)) = sign1.protected.header.content_type {
            if cty != "application/coserv+cbor" {
                Err(CoservError::ContentTypeMismatch)?;
            }
        } else {
            Err(CoservError::VerificationError(
                CoservError::RequiredFieldNotSet("cty".into(), "COSE header".into()).into(),
            ))?
        }

        let Some(ref alg) = sign1.protected.header.alg else {
            Err(CoservError::VerificationError(
                CoservError::RequiredFieldNotSet("alg".into(), "COSE header".into()).into(),
            ))?
        };

        let cose_alg = match alg {
            coset::RegisteredLabelWithPrivate::Assigned(i) => {
                Ok(CoseAlgorithm::try_from(i.to_i64())
                    .map_err(|e| CoservError::VerificationError(e.into()))?)
            }
            coset::RegisteredLabelWithPrivate::PrivateUse(i) => Ok(CoseAlgorithm::try_from(*i)
                .map_err(|e| CoservError::VerificationError(e.into()))?),
            other => Err(CoservError::VerificationError(
                CoservError::Custom(format!("unsupported algorithm in header: {other:?}")).into(),
            )),
        }?;

        if sign1.payload.is_none() {
            Err(CoservError::VerificationError(
                CoservError::RequiredFieldNotSet("payload".into(), "COSE Sign1".into()).into(),
            ))?
        }

        let aad: &[u8] = &[];

        sign1
            .verify_signature(aad, |sig, data| {
                verifier.verify_signature(cose_alg, sig, data)
            })
            .map_err(|e| CoservError::VerificationError(e.into()))?;

        Self::from_cbor(sign1.payload.unwrap().as_slice())
    }
}

/// Builder for CoSERV object
#[derive(Debug, Default)]
pub struct CoservBuilder<'a> {
    pub profile: Option<CoservProfile>,
    pub query: Option<CoservQuery<'a>>,
    pub results: Option<CoservResult<'a>>,
}

impl<'a> CoservBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the profile
    pub fn profile(mut self, value: CoservProfile) -> Self {
        self.profile = Some(value);
        self
    }

    /// Set the query
    pub fn query(mut self, value: CoservQuery<'a>) -> Self {
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
                            builder = builder.profile(access.next_value::<CoservProfile>()?);
                        }
                        Some(1) => {
                            builder = builder.query(access.next_value::<CoservQuery>()?);
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

/// Represents CoSERV profile
#[derive(PartialEq, Debug)]
pub enum CoservProfile {
    /// Byte string representing ASN1 Object Identifier.
    /// Gets serialized as CBOR byte string.
    Oid(ObjectIdentifier),
    /// Text string representing URI
    /// Gets serialized as CBOR text string.
    Uri(String),
}

impl Serialize for CoservProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CoservProfile::Oid(oid) => oid.serialize(serializer),
            CoservProfile::Uri(uri) => uri.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CoservProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ciborium::Value::deserialize(deserializer)? {
            ciborium::Value::Text(uri) => Ok(Self::Uri(uri)),
            ciborium::Value::Bytes(oid) => {
                Ok(Self::Oid(oid.try_into().map_err(|_| {
                    D::Error::custom("cannot convert bytes to OID")
                })?))
            }
            _ => Err(D::Error::custom("invalid profile type choice in cbor")),
        }
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
            "rv-class-simple-results-source-artifacts",
            "rv-class-simple-results",
            "rv-class-simple",
            "rv-class-stateful",
            "rv-class-two-entries",
            "rv-instance-two-entries",
            "rv-results",
            "rv-rim-query",
            "rv-rim-results",
        ];

        let mut path = PathBuf::from("testdata");

        for case in tests.iter() {
            path.push(case);
            path.set_extension("cbor");
            let cbor = fs::read(&path).unwrap();
            let coserv = Coserv::from_cbor(cbor.as_slice()).unwrap();
            let cbor_ser = coserv.to_cbor().unwrap();
            assert_eq!(cbor_ser, cbor, "failed test {}", case);
            path.pop();
        }
    }

    #[test]
    fn test_valid_b64() {
        let tests = [
            "rv-class-simple-results-source-artifacts",
            "rv-class-simple-results",
            "rv-class-simple",
            "rv-class-stateful",
            "rv-class-two-entries",
            "rv-instance-two-entries",
            "rv-results",
            "rv-rim-query",
            "rv-rim-results",
        ];

        let mut path = PathBuf::from("testdata");

        for case in tests.iter() {
            path.push(case);
            path.set_extension("b64u");
            let b64u = fs::read(&path).unwrap();
            let coserv = Coserv::from_b64_url(b64u.as_slice()).unwrap();
            let b64u_ser = coserv.to_b64_url().unwrap();
            assert_eq!(
                Vec::<u8>::from(b64u_ser.as_bytes()),
                b64u,
                "failed test {}",
                case
            );
            path.pop();
        }
    }

    #[test]
    fn test_builder() {
        let builder = CoservBuilder::new();
        assert!(builder.build().is_err());

        let mut builder = CoservBuilder::new();
        builder = builder.profile(CoservProfile::Uri("foo".into()));
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid() {
        let cbor: Vec<u8> = vec![0xa1, 0x04, 0x01];
        let err: Result<Coserv, _> = ciborium::from_reader(cbor.as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_profile() {
        let cbor: Vec<u8> = vec![0xd8, 0x20, 0x63, 0x66, 0x6f, 0x6f]; // tagged (32) type
        let err: Result<Coserv, _> = ciborium::from_reader(cbor.as_slice());
        assert!(err.is_err());

        let tests: Vec<(CoservProfile, Vec<u8>)> = vec![
            (
                CoservProfile::Uri(String::from("foo")),
                vec![0x63, 0x66, 0x6f, 0x6f],
            ),
            (
                CoservProfile::Oid(vec![0x2a_u8, 0x03, 0x04].try_into().unwrap()),
                vec![0x43, 0x2a, 0x03, 0x04],
            ), // 1.2.3.4
            (
                CoservProfile::Oid("1.2.3.4".try_into().unwrap()),
                vec![0x43, 0x2a, 0x03, 0x04],
            ), // 1.2.3.4
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");
        }
    }

    mod sign {
        use super::*;

        struct FakeSigner {}

        impl CoseKeyOwner for FakeSigner {
            fn to_cose_key(&self) -> CoseKey {
                CoseKey::default()
            }
        }

        impl CoseSigner for FakeSigner {
            fn sign(
                &self,
                _alg: CoseAlgorithm,
                _data: &[u8],
            ) -> Result<Vec<u8>, corim_rs::CorimError> {
                Ok(vec![0x00, 0x01, 0x02, 0x04])
            }
        }

        impl CoseVerifier for FakeSigner {
            fn verify_signature(
                &self,
                _alg: CoseAlgorithm,
                sig: &[u8],
                _data: &[u8],
            ) -> Result<(), corim_rs::CorimError> {
                if sig == [0x00, 0x01, 0x02, 0x04] {
                    Ok(())
                } else {
                    Err(corim_rs::CorimError::custom("error"))
                }
            }
        }

        #[test]
        fn test_sign_and_verify() {
            let coserv =
                Coserv::from_cbor(fs::File::open("testdata/rv-results.cbor").unwrap()).unwrap();
            let signer = FakeSigner {};

            let signed = coserv.sign(&signer, CoseAlgorithm::ES384).unwrap();

            let verifier = FakeSigner {};
            let coserv_ex = Coserv::verify_and_extract(&verifier, signed.as_slice()).unwrap();

            assert_eq!(coserv, coserv_ex);
        }
    }
}
