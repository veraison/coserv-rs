// SPDX-License-Identifier: Apache-2.0

use super::common::TimeStamp;
use crate::error::CoservError;
use cmw::CMW;
use corim_rs::core::{ExtensionMap, ExtensionValue};
use corim_rs::triples::{
    AttestKeyTripleRecord, ConditionalEndorsementTripleRecord, CryptoKeyTypeChoice,
    EndorsedTripleRecord, ReferenceTripleRecord,
};
use derive_more::Display;
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, Visitor},
    ser::{Error as SerError, Serialize, SerializeMap, Serializer},
};
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

/// Representation of CoSERV result.
/// Use [CoservResultBuilder] to build this.
#[derive(Debug, PartialEq, Clone)]
pub struct CoservResult<'a> {
    /// result set
    pub result_set: Option<ResultSetTypeChoice<'a>>,
    /// result set expiry
    pub expiry: TimeStamp,
    /// optional field for source artifacts
    pub source_artifacts: Option<Vec<CMW>>,
}

impl Serialize for CoservResult<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // for fixed length encoding of map
        let num_elts = 1
            + self.source_artifacts.is_some() as usize
            + match &self.result_set {
                Some(rs) => match rs {
                    ResultSetTypeChoice::ReferenceValues(_)
                    | ResultSetTypeChoice::TrustAnchors(_) => 1,
                    ResultSetTypeChoice::EndorsedValues(_) => 2,
                    ResultSetTypeChoice::Extensions(m) => m.0.len(),
                },
                None => 0,
            };

        let mut map = serializer.serialize_map(Some(num_elts))?;
        if let Some(rs) = &self.result_set {
            match rs {
                ResultSetTypeChoice::ReferenceValues(rv) => {
                    map.serialize_entry(&0, &rv.rv_quads)?;
                }
                ResultSetTypeChoice::EndorsedValues(ev) => {
                    map.serialize_entry(&1, &ev.ev_quads)?;
                    map.serialize_entry(&2, &ev.cev_quads)?;
                }
                ResultSetTypeChoice::TrustAnchors(ta) => {
                    map.serialize_entry(&3, &ta.ak_quads)?;
                }
                ResultSetTypeChoice::Extensions(ext) => {
                    ext.serialize_map(&mut map, false)?;
                }
            };
        }
        map.serialize_entry(&10, &self.expiry)?;
        if self.source_artifacts.is_some() {
            let wrapper_cmw: Vec<CmwCborRecordType> = self
                .source_artifacts
                .as_ref()
                .unwrap()
                .iter()
                .map(|x| CmwCborRecordType(Cow::Borrowed(x)))
                .collect();
            map.serialize_entry(&11, &wrapper_cmw)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for CoservResult<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoservResultVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CoservResultVisitor<'a> {
            type Value = CoservResult<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "CoSERV result map")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut builder = CoservResultBuilder::new();
                loop {
                    match access.next_key::<i64>()? {
                        Some(0) => {
                            builder
                                .rv_quads(access.next_value::<Vec<ReferenceValuesQuad<'a>>>()?)
                                .map_err(M::Error::custom)?;
                        }
                        Some(1) => {
                            builder
                                .ev_quads(access.next_value::<Vec<EndorsedValuesQuad<'a>>>()?)
                                .map_err(M::Error::custom)?;
                        }
                        Some(2) => {
                            builder
                                .cev_quads(
                                    access.next_value::<Vec<ConditionalEndorsementQuad<'a>>>()?,
                                )
                                .map_err(M::Error::custom)?;
                        }
                        Some(3) => {
                            builder
                                .ak_quads(access.next_value::<Vec<AttestKeyQuad<'a>>>()?)
                                .map_err(M::Error::custom)?;
                        }
                        Some(4) => Err(M::Error::custom("CoTS unimplemented"))?,
                        Some(10) => builder = builder.expiry(access.next_value::<TimeStamp>()?),
                        Some(11) => {
                            let source_artifacts = access.next_value::<Vec<CmwCborRecordType>>()?;
                            let cmws: Vec<CMW> = source_artifacts
                                .into_iter()
                                .map(|x| x.0.into_owned())
                                .collect();
                            builder = builder.source_artifacts(cmws);
                        }
                        Some(n) => {
                            builder
                                .add_extension(n.into(), access.next_value::<ExtensionValue>()?)
                                .map_err(M::Error::custom)?;
                        }
                        None => break,
                    }
                }
                builder.build().map_err(M::Error::custom)
            }
        }
        deserializer.deserialize_map(CoservResultVisitor {
            marker: PhantomData,
        })
    }
}

/// Builder for [CoservResult]
#[derive(Debug, Default, Clone)]
pub struct CoservResultBuilder<'a> {
    pub result_set: Option<ResultSetTypeChoice<'a>>,
    pub expiry: Option<TimeStamp>,
    pub source_artifacts: Option<Vec<CMW>>,
}

impl<'a> CoservResultBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    // these methods are used by deserializer to construct the result set
    // while building coserv result, the result set can be completely
    // built and then set using the result_set method
    fn rv_quads(&mut self, value: Vec<ReferenceValuesQuad<'a>>) -> Result<(), CoservError> {
        if let Some(ref mut res) = self.result_set {
            match res {
                ResultSetTypeChoice::ReferenceValues(ref mut rv) => {
                    rv.rv_quads = value;
                    Ok(())
                }
                other => Err(CoservError::SetQuadsFailed(
                    "rv_quads".to_string(),
                    other.to_string(),
                )),
            }
        } else {
            self.result_set = Some(ResultSetTypeChoice::ReferenceValues(
                ReferenceValuesResult { rv_quads: value },
            ));
            Ok(())
        }
    }

    fn ak_quads(&mut self, value: Vec<AttestKeyQuad<'a>>) -> Result<(), CoservError> {
        if let Some(ref mut res) = self.result_set {
            match res {
                ResultSetTypeChoice::TrustAnchors(ref mut ak) => {
                    ak.ak_quads = value;
                    Ok(())
                }
                other => Err(CoservError::SetQuadsFailed(
                    "ak_quads".to_string(),
                    other.to_string(),
                )),
            }
        } else {
            self.result_set = Some(ResultSetTypeChoice::TrustAnchors(TrustAnchorsResult {
                ak_quads: value,
            }));
            Ok(())
        }
    }

    fn ev_quads(&mut self, value: Vec<EndorsedValuesQuad<'a>>) -> Result<(), CoservError> {
        if let Some(ref mut res) = self.result_set {
            match res {
                ResultSetTypeChoice::EndorsedValues(ref mut ev) => {
                    ev.ev_quads = value;
                    Ok(())
                }
                other => Err(CoservError::SetQuadsFailed(
                    "ev_quads".to_string(),
                    other.to_string(),
                )),
            }
        } else {
            self.result_set = Some(ResultSetTypeChoice::EndorsedValues(EndorsedValuesResult {
                ev_quads: value,
                cev_quads: vec![],
            }));
            Ok(())
        }
    }

    fn cev_quads(&mut self, value: Vec<ConditionalEndorsementQuad<'a>>) -> Result<(), CoservError> {
        if let Some(ref mut res) = self.result_set {
            match res {
                ResultSetTypeChoice::EndorsedValues(ref mut ev) => {
                    ev.cev_quads = value;
                    Ok(())
                }
                other => Err(CoservError::SetQuadsFailed(
                    "cev_quads".to_string(),
                    other.to_string(),
                )),
            }
        } else {
            self.result_set = Some(ResultSetTypeChoice::EndorsedValues(EndorsedValuesResult {
                ev_quads: vec![],
                cev_quads: value,
            }));
            Ok(())
        }
    }

    fn add_extension(&mut self, key: i128, value: ExtensionValue<'a>) -> Result<(), CoservError> {
        if let Some(ref mut res) = self.result_set {
            match res {
                ResultSetTypeChoice::Extensions(ref mut ext) => {
                    ext.insert(key.into(), value);
                    Ok(())
                }
                other => Err(CoservError::SetQuadsFailed(
                    "result set extensions".to_string(),
                    other.to_string(),
                )),
            }
        } else {
            let mut extensions = ExtensionMap::default();
            extensions.insert(key.into(), value);
            self.result_set = Some(ResultSetTypeChoice::Extensions(extensions));
            Ok(())
        }
    }

    pub fn result_set(mut self, value: ResultSetTypeChoice<'a>) -> Self {
        self.result_set = Some(value);
        self
    }

    pub fn expiry(mut self, value: TimeStamp) -> Self {
        self.expiry = Some(value);
        self
    }

    pub fn source_artifacts(mut self, value: Vec<CMW>) -> Self {
        self.source_artifacts = Some(value);
        self
    }

    pub fn build(self) -> Result<CoservResult<'a>, CoservError> {
        if self.result_set.is_none() && self.source_artifacts.is_none() {
            Err(CoservError::InvalidResult(
                "both result-set and source artifacts cannot be empty".into(),
            ))
        } else {
            Ok(CoservResult {
                result_set: self.result_set,
                expiry: self.expiry.ok_or(CoservError::RequiredFieldNotSet(
                    "expiry".into(),
                    "result".into(),
                ))?,
                source_artifacts: self.source_artifacts,
            })
        }
    }
}

/// Result set type: reference values, endorsed values, trust anchors
/// or result set extionsions
#[derive(Debug, PartialEq, Clone, Display)]
pub enum ResultSetTypeChoice<'a> {
    #[display("reference values")]
    ReferenceValues(ReferenceValuesResult<'a>),
    #[display("endorsed values")]
    EndorsedValues(EndorsedValuesResult<'a>),
    #[display("trust anchors")]
    TrustAnchors(TrustAnchorsResult<'a>),
    #[display("result set extensions")]
    Extensions(ExtensionMap<'a>),
}

/// Represents reference value quad.
/// Use [ReferenceValuesQuadBuilder] to build this.
pub type ReferenceValuesQuad<'a> = QuadType<'a, ReferenceTripleRecord<'a>>;

/// Represents endorsed value quad.
/// Use [EndorsedValuesQuadBuilder] to build this.
pub type EndorsedValuesQuad<'a> = QuadType<'a, EndorsedTripleRecord<'a>>;

/// Represents conditional endorsement quad.
/// Use [ConditionalEndorsementQuadBuilder] to build this.
pub type ConditionalEndorsementQuad<'a> = QuadType<'a, ConditionalEndorsementTripleRecord<'a>>;

/// Represents attest key quad.
/// Use [AttestKeyQuadBuilder] to build this.
pub type AttestKeyQuad<'a> = QuadType<'a, AttestKeyTripleRecord<'a>>;

/// Builder for [ReferenceValuesQuad]
pub type ReferenceValuesQuadBuilder<'a> = QuadBuilder<'a, ReferenceTripleRecord<'a>>;

/// Builder for [EndorsedValuesQuad]
pub type EndorsedValuesQuadBuilder<'a> = QuadBuilder<'a, EndorsedTripleRecord<'a>>;

/// Builder for [ConditionalEndorsementQuad]
pub type ConditionalEndorsementQuadBuilder<'a> =
    QuadBuilder<'a, ConditionalEndorsementTripleRecord<'a>>;

/// Builder for [AttestKeyQuad]
pub type AttestKeyQuadBuilder<'a> = QuadBuilder<'a, AttestKeyTripleRecord<'a>>;

// empty trait to bound which triples can
// be used by QuadType<T>
trait AcceptedTriples {}

impl AcceptedTriples for ReferenceTripleRecord<'_> {}
impl AcceptedTriples for EndorsedTripleRecord<'_> {}
impl AcceptedTriples for ConditionalEndorsementTripleRecord<'_> {}
impl AcceptedTriples for AttestKeyTripleRecord<'_> {}

/// represents reference-values group from
/// <https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-result-set-structure>
#[derive(Debug, PartialEq, Clone)]
pub struct ReferenceValuesResult<'a> {
    pub rv_quads: Vec<ReferenceValuesQuad<'a>>,
}

/// represents endorsed-values group from
/// <https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-result-set-structure>
#[derive(Debug, PartialEq, Clone)]
pub struct EndorsedValuesResult<'a> {
    pub ev_quads: Vec<EndorsedValuesQuad<'a>>,
    pub cev_quads: Vec<ConditionalEndorsementQuad<'a>>,
}

/// represents trust-anchors group from
/// <https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-result-set-structure>
#[derive(Debug, PartialEq, Clone)]
pub struct TrustAnchorsResult<'a> {
    pub ak_quads: Vec<AttestKeyQuad<'a>>,
    //TODO: CoTS
}

/// Generic type used to define quads.
/// Use [ReferenceValuesQuad], [EndorsedValuesQuad],
/// [ConditionalEndorsementQuad], [AttestKeyQuad] instead
#[allow(private_bounds)]
#[derive(Debug, PartialEq, Clone)]
pub struct QuadType<'a, T>
where
    T: Serialize + AcceptedTriples,
{
    pub authorities: Vec<CryptoKeyTypeChoice<'a>>,
    pub triple: T,
}

/// Builder for [QuadType]
/// Use [ReferenceValuesQuadBuilder], [EndorsedValuesQuadBuilder],
/// [ConditionalEndorsementQuadBuilder], [AttestKeyQuadBuilder] instead
#[allow(private_bounds)]
#[derive(Debug)]
pub struct QuadBuilder<'a, T>
where
    T: Serialize + AcceptedTriples,
{
    authorities: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    triple: Option<T>,
}

impl<T> Default for QuadBuilder<'_, T>
where
    T: Serialize + AcceptedTriples,
{
    fn default() -> Self {
        QuadBuilder {
            authorities: None,
            triple: None,
        }
    }
}

#[allow(private_bounds)]
impl<'a, T> QuadBuilder<'a, T>
where
    T: Serialize + AcceptedTriples,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn triple(mut self, value: T) -> Self {
        self.triple = Some(value);
        self
    }

    pub fn add_authority(&mut self, value: CryptoKeyTypeChoice<'a>) {
        if let Some(ref mut au) = self.authorities {
            au.push(value);
        } else {
            self.authorities = Some(vec![value]);
        }
    }

    pub fn authorities(mut self, value: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.authorities = Some(value);
        self
    }

    pub fn build(self) -> Result<QuadType<'a, T>, CoservError> {
        Ok(QuadType {
            authorities: self.authorities.ok_or(CoservError::RequiredFieldNotSet(
                "authorities".into(),
                "quad".into(),
            ))?,
            triple: self.triple.ok_or(CoservError::RequiredFieldNotSet(
                "triples".into(),
                "quad".into(),
            ))?,
        })
    }
}

impl<T> Serialize for QuadType<'_, T>
where
    T: Serialize + AcceptedTriples,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(&1, &self.authorities)?;
        map.serialize_entry(&2, &self.triple)?;
        map.end()
    }
}

impl<'de, 'a, T> Deserialize<'de> for QuadType<'a, T>
where
    T: Serialize + Deserialize<'de> + AcceptedTriples + 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(QuadTypeVisitor::<'a, T> {
            marker: PhantomData,
        })
    }
}

struct QuadTypeVisitor<'a, T> {
    marker: PhantomData<&'a T>,
}

impl<'de, 'a, T> Visitor<'de> for QuadTypeVisitor<'a, T>
where
    T: Serialize + Deserialize<'de> + AcceptedTriples + 'a,
{
    type Value = QuadType<'a, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "CoSERV quad type")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut builder = QuadBuilder::new();
        loop {
            match access.next_key::<i64>()? {
                Some(1) => {
                    builder =
                        builder.authorities(access.next_value::<Vec<CryptoKeyTypeChoice<'a>>>()?)
                }
                Some(2) => builder = builder.triple(access.next_value::<T>()?),
                Some(n) => Err(M::Error::unknown_field(n.to_string().as_str(), &["1", "2"]))?,
                None => break,
            };
        }
        builder.build().map_err(M::Error::custom)
    }
}

// wrapper around cmw::CMW that implements Serialize, Deserialize from serde
#[derive(Debug, PartialEq)]
struct CmwCborRecordType<'a>(Cow<'a, CMW>);

impl Serialize for CmwCborRecordType<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let cbor = self.0.marshal_cbor().map_err(S::Error::custom)?;
        let value = ciborium::from_reader::<ciborium::Value, &[u8]>(cbor.as_slice())
            .map_err(S::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CmwCborRecordType<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;
        let mut cbor: Vec<u8> = vec![];
        ciborium::into_writer(&value, &mut cbor).map_err(D::Error::custom)?;
        let record = CMW::unmarshal_cbor(cbor.as_slice()).map_err(D::Error::custom)?;
        Ok(CmwCborRecordType(Cow::Owned(record)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use cmw::monad::Monad;
    use cmw::Mime;
    use corim_rs::triples::MeasurementValuesMap;
    use corim_rs::triples::{
        AttestKeyTripleRecord, ConditionalEndorsementTripleRecord, CryptoKeyTypeChoice,
        EndorsedTripleRecord, InstanceIdTypeChoice, MeasurementMap, ReferenceTripleRecord,
    };
    use corim_rs::{Bytes, EnvironmentMap, StatefulEnvironmentRecord, TriplesRecordCondition};
    use std::str::FromStr;

    #[test]
    fn test_cmw_wrapper() {
        let cmw = CMW::Monad(
            Monad::new(
                Mime::from_str("application/vnd.example.refvals").unwrap(),
                vec![0x01, 0x02, 0x03, 0x04],
                None,
            )
            .unwrap(),
        );
        // need to marshal and unmarshal to set the format field
        let cmw_cbor = cmw.marshal_cbor().unwrap();
        let cmw = CMW::unmarshal_cbor(cmw_cbor.as_slice()).unwrap();

        let tests: Vec<(CmwCborRecordType, Vec<u8>)> =
            vec![(CmwCborRecordType(Cow::Owned(cmw)), cmw_cbor)];
        for (i, (val, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&val, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {val:?}");

            let val_de: CmwCborRecordType = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(*val, val_de, "de at index {i}: {val:?} != {val_de:?}");
        }
    }

    #[test]
    fn test_reference_values_quad() {
        let m1 = MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        };
        let tests: Vec<(ReferenceValuesQuad, Vec<u8>)> = vec![(
            ReferenceValuesQuad {
                authorities: vec![
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                ],
                triple: ReferenceTripleRecord {
                    ref_env: EnvironmentMap {
                        class: None,
                        instance: Some(InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        group: None,
                    },
                    ref_claims: vec![MeasurementMap {
                        mkey: None,
                        mval: m1.clone(),
                        authorized_by: None,
                    }],
                },
            },
            vec![
                0xa2, // map(2)
                0x01, // unsigned(1)
                0x82, // array(2)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                0x02, // unsigned(2)
                0x82, // array(2)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x0b, // unsigned(11)
                0x63, // text(3)
                0x66, 0x6f, 0x6f, // "foo"
            ],
        )];
        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: ReferenceValuesQuad =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<ReferenceValuesQuad, _> =
            ciborium::from_reader([0xa1, 0x03, 0x80].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_endorsed_values_quad() {
        let m1 = MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        };
        let tests: Vec<(EndorsedValuesQuad, Vec<u8>)> = vec![(
            EndorsedValuesQuad {
                authorities: vec![
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                ],
                triple: EndorsedTripleRecord {
                    condition: EnvironmentMap {
                        class: None,
                        instance: Some(InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        group: None,
                    },
                    endorsement: vec![MeasurementMap {
                        mkey: None,
                        mval: m1.clone(),
                        authorized_by: None,
                    }],
                },
            },
            vec![
                0xa2, // map(2)
                0x01, // unsigned(1)
                0x82, // array(2)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                0x02, // unsigned(2)
                0x82, // array(2)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x0b, // unsigned(11)
                0x63, // text(3)
                0x66, 0x6f, 0x6f, // "foo"
            ],
        )];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: EndorsedValuesQuad =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<EndorsedValuesQuad, _> =
            ciborium::from_reader([0xa1, 0x03, 0x80].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_conditional_endorsement_quad() {
        let (m1, m2) = (
            MeasurementValuesMap {
                name: Some("foo".into()),
                ..Default::default()
            },
            MeasurementValuesMap {
                name: Some("bar".into()),
                ..Default::default()
            },
        );
        let tests: Vec<(ConditionalEndorsementQuad, Vec<u8>)> = vec![(
            ConditionalEndorsementQuad {
                authorities: vec![
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                ],
                triple: ConditionalEndorsementTripleRecord {
                    conditions: vec![StatefulEnvironmentRecord {
                        environment: EnvironmentMap {
                            class: None,
                            instance: Some(InstanceIdTypeChoice::Bytes(
                                Bytes::from(vec![1, 2, 3, 4]).into(),
                            )),
                            group: None,
                        },
                        claims_list: vec![MeasurementMap {
                            mkey: None,
                            mval: m1.clone(),
                            authorized_by: None,
                        }],
                    }],
                    endorsements: vec![EndorsedTripleRecord {
                        condition: EnvironmentMap {
                            class: None,
                            instance: Some(InstanceIdTypeChoice::Bytes(
                                Bytes::from(vec![1, 2, 3, 4]).into(),
                            )),
                            group: None,
                        },
                        endorsement: vec![MeasurementMap {
                            mkey: None,
                            mval: m2.clone(),
                            authorized_by: None,
                        }],
                    }],
                },
            },
            vec![
                0xa2, // map(2)
                0x01, // unsigned(1)
                0x82, // array(2)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                0x02, // unsigned(2)
                0x82, // array(2)
                0x81, //
                0x82, // array(2)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x0b, // unsigned(11)
                0x63, // text(3)
                0x66, 0x6f, 0x6f, // "foo"
                0x81, 0x82, // array(2)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x0b, // unsigned(11)
                0x63, // text(3)
                0x62, 0x61, 0x72, // "bar"
            ],
        )];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: ConditionalEndorsementQuad =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }
    }

    #[test]
    fn test_attest_key_quad() {
        let tests: Vec<(AttestKeyQuad, Vec<u8>)> = vec![(
            AttestKeyQuad {
                authorities: vec![
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                ],
                triple: AttestKeyTripleRecord {
                    environment: EnvironmentMap {
                        class: None,
                        instance: Some(InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        group: None,
                    },
                    key_list: vec![CryptoKeyTypeChoice::Bytes(
                        Bytes::from(vec![1, 2, 3, 4]).into(),
                    )],
                    conditions: Some(TriplesRecordCondition {
                        mkey: Some("foo".into()),
                        authorized_by: None,
                    }),
                },
            },
            vec![
                0xa2, // map(2)
                0x01, // unsigned(1)
                0x82, // array(2)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                0x02, // unsigned(2)
                0x83, // array(3)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0xa1, // map(1)
                0x00, // unsigned(0)
                0x63, // text(3)
                0x66, 0x6f, 0x6f, // "foo"
            ],
        )];
        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            // Fix corim-rs
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: AttestKeyQuad = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }
    }

    #[test]
    fn test_coserv_result() {
        let m1 = MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        };
        let cmw = CMW::Monad(
            Monad::new(
                Mime::from_str("application/vnd.example.refvals").unwrap(),
                vec![0x01, 0x02, 0x03, 0x04],
                None,
            )
            .unwrap(),
        );
        // need to marshal and unmarshal to set the format to cborrecord
        let cmw_cbor = cmw.marshal_cbor().unwrap();
        let cmw = CMW::unmarshal_cbor(cmw_cbor.as_slice()).unwrap();
        let tests: Vec<(CoservResult, Vec<u8>)> = vec![
            (
                CoservResult {
                    result_set: Some(ResultSetTypeChoice::ReferenceValues(
                        ReferenceValuesResult {
                            rv_quads: vec![ReferenceValuesQuad {
                                authorities: vec![
                                    CryptoKeyTypeChoice::Bytes(
                                        Bytes::from(vec![1, 2, 3, 4]).into(),
                                    ),
                                    CryptoKeyTypeChoice::Bytes(
                                        Bytes::from(vec![2, 3, 4, 5]).into(),
                                    ),
                                ],
                                triple: ReferenceTripleRecord {
                                    ref_env: EnvironmentMap {
                                        class: None,
                                        instance: Some(InstanceIdTypeChoice::Bytes(
                                            Bytes::from(vec![1, 2, 3, 4]).into(),
                                        )),
                                        group: None,
                                    },
                                    ref_claims: vec![MeasurementMap {
                                        mkey: None,
                                        mval: m1.clone(),
                                        authorized_by: None,
                                    }],
                                },
                            }],
                        },
                    )),
                    expiry: DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                        .unwrap()
                        .into(),
                    source_artifacts: None,
                },
                vec![
                    0xa2, 0x00, 0x81, 0xa2, // map(2)
                    0x01, // unsigned(1)
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                    0x02, // unsigned(2)
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                    0x0a, 0xc0, 0x74, // tag(0), text(20)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33,
                    0x3a, 0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a,
                ],
            ),
            (
                CoservResult {
                    result_set: Some(ResultSetTypeChoice::ReferenceValues(
                        ReferenceValuesResult {
                            rv_quads: vec![ReferenceValuesQuad {
                                authorities: vec![
                                    CryptoKeyTypeChoice::Bytes(
                                        Bytes::from(vec![1, 2, 3, 4]).into(),
                                    ),
                                    CryptoKeyTypeChoice::Bytes(
                                        Bytes::from(vec![2, 3, 4, 5]).into(),
                                    ),
                                ],
                                triple: ReferenceTripleRecord {
                                    ref_env: EnvironmentMap {
                                        class: None,
                                        instance: Some(InstanceIdTypeChoice::Bytes(
                                            Bytes::from(vec![1, 2, 3, 4]).into(),
                                        )),
                                        group: None,
                                    },
                                    ref_claims: vec![MeasurementMap {
                                        mkey: None,
                                        mval: m1.clone(),
                                        authorized_by: None,
                                    }],
                                },
                            }],
                        },
                    )),
                    expiry: DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                        .unwrap()
                        .into(),
                    source_artifacts: Some(vec![cmw]),
                },
                vec![
                    0xa3, 0x00, 0x81, 0xa2, // map(2)
                    0x01, // unsigned(1)
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                    0x02, // unsigned(2)
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                    0x0a, 0xc0, 0x74, // tag(0), text(20)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33,
                    0x3a, 0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a, 0x0b, 0x81, 0x82, // array(2)
                    0x78, 0x1f, // text(31)
                    0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76,
                    0x6e, 0x64, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x72, 0x65,
                    0x66, 0x76, 0x61, 0x6c, 0x73, // "application/vnd.example.refvals"
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                ],
            ),
        ];
        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: CoservResult = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }
    }

    #[test]
    fn test_coserv_result_builder() {
        let cmw = CMW::Monad(
            Monad::new(
                Mime::from_str("application/vnd.example.refvals").unwrap(),
                vec![0x01, 0x02, 0x03, 0x04],
                None,
            )
            .unwrap(),
        );

        // result set contains only source artifiacts
        let builder = CoservResultBuilder::new()
            .expiry(
                DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                    .unwrap()
                    .into(),
            )
            .source_artifacts(vec![cmw.clone()]);

        assert!(builder.build().is_ok());

        // tests for SetQuadsFailed error
        let (m1, m2) = (
            MeasurementValuesMap {
                name: Some("foo".into()),
                ..Default::default()
            },
            MeasurementValuesMap {
                name: Some("bar".into()),
                ..Default::default()
            },
        );
        let rv_quad = ReferenceValuesQuad {
            authorities: vec![
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
            ],
            triple: ReferenceTripleRecord {
                ref_env: EnvironmentMap {
                    class: None,
                    instance: Some(InstanceIdTypeChoice::Bytes(
                        Bytes::from(vec![1, 2, 3, 4]).into(),
                    )),
                    group: None,
                },
                ref_claims: vec![MeasurementMap {
                    mkey: None,
                    mval: m1.clone(),
                    authorized_by: None,
                }],
            },
        };

        let ev_quad = EndorsedValuesQuad {
            authorities: vec![
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
            ],
            triple: EndorsedTripleRecord {
                condition: EnvironmentMap {
                    class: None,
                    instance: Some(InstanceIdTypeChoice::Bytes(
                        Bytes::from(vec![1, 2, 3, 4]).into(),
                    )),
                    group: None,
                },
                endorsement: vec![MeasurementMap {
                    mkey: None,
                    mval: m1.clone(),
                    authorized_by: None,
                }],
            },
        };

        let cev_quad = ConditionalEndorsementQuad {
            authorities: vec![
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
            ],
            triple: ConditionalEndorsementTripleRecord {
                conditions: vec![StatefulEnvironmentRecord {
                    environment: EnvironmentMap {
                        class: None,
                        instance: Some(InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        group: None,
                    },
                    claims_list: vec![MeasurementMap {
                        mkey: None,
                        mval: m1.clone(),
                        authorized_by: None,
                    }],
                }],
                endorsements: vec![EndorsedTripleRecord {
                    condition: EnvironmentMap {
                        class: None,
                        instance: Some(InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        group: None,
                    },
                    endorsement: vec![MeasurementMap {
                        mkey: None,
                        mval: m2.clone(),
                        authorized_by: None,
                    }],
                }],
            },
        };

        let ak_quad = AttestKeyQuad {
            authorities: vec![
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
            ],
            triple: AttestKeyTripleRecord {
                environment: EnvironmentMap {
                    class: None,
                    instance: Some(InstanceIdTypeChoice::Bytes(
                        Bytes::from(vec![1, 2, 3, 4]).into(),
                    )),
                    group: None,
                },
                key_list: vec![CryptoKeyTypeChoice::Bytes(
                    Bytes::from(vec![1, 2, 3, 4]).into(),
                )],
                conditions: Some(TriplesRecordCondition {
                    mkey: Some("foo".into()),
                    authorized_by: None,
                }),
            },
        };

        let builder = CoservResultBuilder::new();
        let err = builder.build();
        assert!(err.is_err());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(
            DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                .unwrap()
                .into(),
        );
        let err = builder.build();
        assert!(err.is_err());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(
            DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                .unwrap()
                .into(),
        );
        assert!(builder.rv_quads(vec![rv_quad.clone()]).is_ok());
        assert!(builder.rv_quads(vec![rv_quad.clone()]).is_ok());
        assert!(builder.ev_quads(vec![ev_quad.clone()]).is_err());
        assert!(builder.cev_quads(vec![cev_quad.clone()]).is_err());
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_err());
        assert!(builder.build().is_ok());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(
            DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                .unwrap()
                .into(),
        );
        assert!(builder.ev_quads(vec![ev_quad.clone()]).is_ok());
        assert!(builder.ev_quads(vec![ev_quad.clone()]).is_ok());
        assert!(builder.cev_quads(vec![cev_quad.clone()]).is_ok());
        assert!(builder.cev_quads(vec![cev_quad.clone()]).is_ok());
        assert!(builder.rv_quads(vec![rv_quad.clone()]).is_err());
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_err());
        assert!(builder.build().is_ok());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(
            DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                .unwrap()
                .into(),
        );
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_ok());
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_ok());
        assert!(builder.ev_quads(vec![ev_quad.clone()]).is_err());
        assert!(builder.cev_quads(vec![cev_quad.clone()]).is_err());
        assert!(builder.rv_quads(vec![rv_quad.clone()]).is_err());
        assert!(builder.build().is_ok());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(
            DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                .unwrap()
                .into(),
        );
        assert!(builder.add_extension(20, ExtensionValue::Null).is_ok());
        assert!(builder.add_extension(20, ExtensionValue::Null).is_ok());
        assert!(builder.add_extension(21, ExtensionValue::Null).is_ok());
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_err());
        assert!(builder.ak_quads(vec![ak_quad.clone()]).is_err());
        assert!(builder.ev_quads(vec![ev_quad.clone()]).is_err());
        assert!(builder.cev_quads(vec![cev_quad.clone()]).is_err());
        assert!(builder.rv_quads(vec![rv_quad.clone()]).is_err());
        assert!(builder.build().is_ok());

        // result set contains both source and collected artifacts
        let builder = CoservResultBuilder::new()
            .expiry(
                DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                    .unwrap()
                    .into(),
            )
            .source_artifacts(vec![cmw.clone()])
            .result_set(ResultSetTypeChoice::ReferenceValues(
                ReferenceValuesResult {
                    rv_quads: vec![rv_quad.clone()],
                },
            ));
        assert!(builder.build().is_ok());
    }
}
