// SPDX-License-Identifier: Apache-2.0

use super::common::TimeStamp;
use crate::error::CoservError;
use cmw::CMW;
use corim_rs::triples::{
    AttestKeyTripleRecord, ConditionalEndorsementTripleRecord, CryptoKeyTypeChoice,
    EndorsedTripleRecord, ReferenceTripleRecord,
};
use derive_more::{Display, From};
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
    /// result type for RIM query
    pub rim_result: Option<CMW>,
}

impl CoservResult<'_> {
    /// Checks if result is empty.
    /// An empty result only contains expiry field.
    pub fn is_empty(&self) -> bool {
        // check if environment results are non-empty
        if let Some(result_set) = &self.result_set {
            match result_set {
                ResultSetTypeChoice::ReferenceValues(rv_res) => {
                    if !rv_res.rv_quads.is_empty() {
                        return false;
                    }
                }
                ResultSetTypeChoice::EndorsedValues(ev_res) => {
                    if !ev_res.ev_quads.is_empty() || !ev_res.cev_quads.is_empty() {
                        return false;
                    }
                }
                ResultSetTypeChoice::TrustAnchors(ta_res) => {
                    if !ta_res.ak_quads.is_empty() {
                        return false;
                    }
                }
            }
        }

        // check if source artifacts result is set
        if self.source_artifacts.is_some() {
            return false;
        }

        // check if RIM result is present
        if self.rim_result.is_some() {
            return false;
        }

        true
    }
}

impl Serialize for CoservResult<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // for fixed length encoding of map
        let num_elts = 1
            + self.source_artifacts.is_some() as usize
            + self.rim_result.is_some() as usize
            + match &self.result_set {
                Some(rs) => match rs {
                    ResultSetTypeChoice::ReferenceValues(_) => 1,
                    ResultSetTypeChoice::TrustAnchors(_) => 2,
                    ResultSetTypeChoice::EndorsedValues(_) => 2,
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
                    // insert empty array so that the CDDL is exactly followed
                    // TODO: fix this once CoTS is implemented
                    map.serialize_entry(&4, &Vec::<u8>::new())?;
                }
            };
        }
        if let Some(rim) = &self.rim_result {
            let wrapper_cmw: CmwCborType = CmwCborType(Cow::Borrowed(rim));
            map.serialize_entry(&5, &wrapper_cmw)?;
        }
        map.serialize_entry(&10, &self.expiry)?;
        if let Some(ref source_artifacts) = self.source_artifacts {
            let wrapper_cmw: Vec<CmwCborType> = source_artifacts
                .iter()
                .map(|x| CmwCborType(Cow::Borrowed(x)))
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
                let mut rs_builder = ResultSetBuilder::new();
                loop {
                    match access.next_key::<i64>()? {
                        Some(0) => {
                            rs_builder
                                .set_rvq(access.next_value::<Vec<ReferenceValuesQuad<'a>>>()?);
                        }
                        Some(1) => {
                            rs_builder.set_evq(access.next_value::<Vec<EndorsedValuesQuad<'a>>>()?);
                        }
                        Some(2) => rs_builder
                            .set_ceq(access.next_value::<Vec<ConditionalEndorsementQuad<'a>>>()?),
                        Some(3) => {
                            rs_builder.set_akq(access.next_value::<Vec<AttestKeyQuad<'a>>>()?)
                        }
                        Some(4) => {
                            let val = access.next_value::<Vec<ciborium::Value>>()?;
                            if !val.is_empty() {
                                Err(M::Error::custom("CoTS is unimplemented"))?
                            }
                            // Allow empty cots list to enable round-tripping
                            rs_builder.set_cots()
                        }
                        Some(10) => builder = builder.expiry(access.next_value::<TimeStamp>()?),
                        Some(11) => {
                            let source_artifacts = access.next_value::<Vec<CmwCborType>>()?;
                            let cmws: Vec<CMW> = source_artifacts
                                .into_iter()
                                .map(|x| x.0.into_owned())
                                .collect();
                            builder = builder.source_artifacts(cmws);
                        }
                        Some(5) => {
                            let rim_results = access.next_value::<CmwCborType>()?.0.into_owned();
                            builder = builder.rim_result(rim_results);
                        }
                        Some(n) => Err(M::Error::unknown_field(
                            n.to_string().as_ref(),
                            &["0", "1", "2", "3", "4", "5", "10", "11"],
                        ))?,
                        None => break,
                    }
                }
                builder.result_set = rs_builder.deserializer_build().map_err(M::Error::custom)?;
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
    pub rim_result: Option<CMW>,
}

impl<'a> CoservResultBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
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

    pub fn rim_result(mut self, value: CMW) -> Self {
        self.rim_result = Some(value);
        self
    }

    pub fn build(self) -> Result<CoservResult<'a>, CoservError> {
        self.valid()?;
        Ok(CoservResult {
            result_set: self.result_set,
            expiry: self.expiry.ok_or(CoservError::RequiredFieldNotSet(
                "expiry".into(),
                "result".into(),
            ))?,
            source_artifacts: self.source_artifacts,
            rim_result: self.rim_result,
        })
    }

    fn valid(&self) -> Result<(), CoservError> {
        match (&self.result_set, &self.source_artifacts, &self.rim_result) {
            (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => Err(CoservError::InvalidResult(
                "both environment-results and rim-results set".into(),
            ))?,
            _ => (),
        };
        // check if rim result is a cmw collection
        if let Some(ref rr) = self.rim_result {
            if !matches!(rr, CMW::Collection(_)) {
                Err(CoservError::InvalidResult(
                    "RIM result is not CMW collection".into(),
                ))?;
            }
        }
        // check if source artifacts are all cmw records
        if let Some(ref sa) = self.source_artifacts {
            if sa.is_empty() {
                Err(CoservError::InvalidResult(
                    "source artifacts array is empty".into(),
                ))?;
            }
            for (i, c) in sa.iter().enumerate() {
                if !matches!(c, CMW::Monad(_)) {
                    Err(CoservError::InvalidResult(format!(
                        "source artifacts at index {i} is not a CMW record"
                    )))?;
                }
            }
        }
        Ok(())
    }
}

/// Result set type: reference values, endorsed values, trust anchors
/// or result set extensions. Use [ResultSetBuilder] to build this.
#[derive(Debug, PartialEq, Clone, Display, From)]
pub enum ResultSetTypeChoice<'a> {
    #[display("reference values")]
    ReferenceValues(ReferenceValuesResult<'a>),
    #[display("endorsed values")]
    EndorsedValues(EndorsedValuesResult<'a>),
    #[display("trust anchors")]
    TrustAnchors(TrustAnchorsResult<'a>),
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
struct CmwCborType<'a>(Cow<'a, CMW>);

impl Serialize for CmwCborType<'_> {
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

impl<'de> Deserialize<'de> for CmwCborType<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;
        let mut cbor: Vec<u8> = vec![];
        ciborium::into_writer(&value, &mut cbor).map_err(D::Error::custom)?;
        let record = CMW::unmarshal_cbor(cbor.as_slice()).map_err(D::Error::custom)?;
        Ok(CmwCborType(Cow::Owned(record)))
    }
}

/// Deserializer's representation of result set
#[derive(Debug, PartialEq, Default, Clone)]
pub struct ResultSetBuilder<'a> {
    rvq: Option<Vec<ReferenceValuesQuad<'a>>>,
    evq: Option<Vec<EndorsedValuesQuad<'a>>>,
    ceq: Option<Vec<ConditionalEndorsementQuad<'a>>>,
    akq: Option<Vec<AttestKeyQuad<'a>>>,
    // this field is to detect a partial trust-anchors group
    // both akq and tas should be present. But since cots
    // is not implemented in rust, codepoint 4 (tas) should
    // be an empty array whenever codepoint 3 (akq) is set.
    cots: Option<()>,
}

impl<'a> ResultSetBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rvq(mut self, rvq: Vec<ReferenceValuesQuad<'a>>) -> Self {
        self.set_rvq(rvq);
        self
    }

    pub fn evq(mut self, evq: Vec<EndorsedValuesQuad<'a>>) -> Self {
        self.set_evq(evq);
        if self.ceq.is_none() {
            self.ceq = Some(Vec::new());
        }
        self
    }

    pub fn ceq(mut self, ceq: Vec<ConditionalEndorsementQuad<'a>>) -> Self {
        self.set_ceq(ceq);
        if self.evq.is_none() {
            self.evq = Some(Vec::new());
        }
        self
    }

    pub fn akq(mut self, akq: Vec<AttestKeyQuad<'a>>) -> Self {
        self.set_akq(akq);
        self.set_cots();
        self
    }

    pub fn add_rvq(&mut self, rvq: ReferenceValuesQuad<'a>) {
        if self.rvq.is_none() {
            self.rvq = Some(vec![rvq]);
        } else {
            if let Some(v) = self.rvq.as_mut() {
                v.push(rvq)
            }
        }
    }

    pub fn add_evq(&mut self, evq: EndorsedValuesQuad<'a>) {
        if self.evq.is_none() {
            self.evq = Some(vec![evq]);
        } else {
            if let Some(v) = self.evq.as_mut() {
                v.push(evq)
            }
        }
        if self.ceq.is_none() {
            self.ceq = Some(Vec::new());
        }
    }

    pub fn add_ceq(&mut self, ceq: ConditionalEndorsementQuad<'a>) {
        if self.ceq.is_none() {
            self.ceq = Some(vec![ceq]);
        } else {
            if let Some(v) = self.ceq.as_mut() {
                v.push(ceq)
            }
        }
        if self.evq.is_none() {
            self.evq = Some(Vec::new());
        }
    }

    pub fn add_akq(&mut self, akq: AttestKeyQuad<'a>) {
        if self.akq.is_none() {
            self.akq = Some(vec![akq]);
        } else {
            if let Some(v) = self.akq.as_mut() {
                v.push(akq)
            }
        }
        self.set_cots();
    }

    pub fn build(self) -> Result<ResultSetTypeChoice<'a>, CoservError> {
        self.deserializer_build()?
            .ok_or(CoservError::custom("result set is empty"))
    }

    // The methods below are used during deserialize to build result set.
    fn reference_values(&mut self) -> Result<Option<ReferenceValuesResult<'a>>, CoservError> {
        Ok(self
            .rvq
            .take()
            .map(|rv_quads| ReferenceValuesResult { rv_quads }))
    }

    fn endorsed_values(&mut self) -> Result<Option<EndorsedValuesResult<'a>>, CoservError> {
        match (self.evq.take(), self.ceq.take()) {
            (Some(ev_quads), Some(cev_quads)) => Ok(Some(EndorsedValuesResult {
                ev_quads,
                cev_quads,
            })),
            (None, None) => Ok(None),
            _ => Err(CoservError::InvalidResult(
                "endorsed values result is incomplete".into(),
            )),
        }
    }

    fn trust_anchors(&mut self) -> Result<Option<TrustAnchorsResult<'a>>, CoservError> {
        match (self.akq.take(), self.cots) {
            (Some(ak_quads), Some(_)) => Ok(Some(TrustAnchorsResult { ak_quads })),
            (None, None) => Ok(None),
            _ => Err(CoservError::InvalidResult(
                "trust anchors result is incomplete".into(),
            )),
        }
    }

    fn set_rvq(&mut self, rvq: Vec<ReferenceValuesQuad<'a>>) {
        self.rvq = Some(rvq);
    }

    fn set_evq(&mut self, evq: Vec<EndorsedValuesQuad<'a>>) {
        self.evq = Some(evq);
    }

    fn set_ceq(&mut self, ceq: Vec<ConditionalEndorsementQuad<'a>>) {
        self.ceq = Some(ceq);
    }

    fn set_akq(&mut self, akq: Vec<AttestKeyQuad<'a>>) {
        self.akq = Some(akq);
    }

    fn set_cots(&mut self) {
        self.cots = Some(());
    }

    fn deserializer_build(mut self) -> Result<Option<ResultSetTypeChoice<'a>>, CoservError> {
        match (
            self.reference_values()?,
            self.endorsed_values()?,
            self.trust_anchors()?,
        ) {
            (Some(rv), None, None) => Ok(Some(rv.into())),
            (None, Some(ev), None) => Ok(Some(ev.into())),
            (None, None, Some(ta)) => Ok(Some(ta.into())),
            (None, None, None) => Ok(None),
            _ => Err(CoservError::InvalidResult(
                "more than one artifact type present in result set".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use cmw::Mime;
    use cmw::{
        collection::{Collection, Label},
        monad::Monad,
    };
    use corim_rs::triples::MeasurementValuesMap;
    use corim_rs::triples::{
        AttestKeyTripleRecord, ConditionalEndorsementTripleRecord, CryptoKeyTypeChoice,
        EndorsedTripleRecord, InstanceIdTypeChoice, MeasurementMap, ReferenceTripleRecord,
    };
    use corim_rs::{
        Bytes, EnvironmentMap, EnvironmentMapBuilder, StatefulEnvironmentRecord,
        TriplesRecordCondition,
    };
    use std::str::FromStr;

    fn get_cmw_record() -> CMW {
        let cmw: CMW = Monad::new_media_type(
            Mime::from_str("application/vnd.example.refvals").unwrap(),
            vec![0x01, 0x02, 0x03, 0x04],
            None,
        )
        .unwrap()
        .into();
        // need to marshal and unmarshal to set the format field
        CMW::unmarshal_cbor(cmw.marshal_cbor().unwrap().as_slice()).unwrap()
    }

    #[rustfmt::skip]
    fn cmw_record_bytes() -> Vec<u8> {
        vec![
0x82, // array(2)
    0x78, 0x1f, // text(31)
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76,
        0x6e, 0x64, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x72, 0x65,
        0x66, 0x76, 0x61, 0x6c, 0x73, // "application/vnd.example.refvals"
    0x44, // bytes(4)
        0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        ]
    }

    fn get_cmw_collection() -> CMW {
        let mut coll = Collection::new(None, None).unwrap();
        coll.add_item(Label::Str("foo".into()), get_cmw_record())
            .unwrap();
        let cmw: CMW = coll.into();
        // need to marshal and unmarshal to set the format field
        CMW::unmarshal_cbor(cmw.marshal_cbor().unwrap().as_slice()).unwrap()
    }

    #[rustfmt::skip]
    fn cmw_collection_bytes() -> Vec<u8> {
        [
&[
0xA1, // map(1)
    0x63, 0x66, 0x6F, 0x6F, // key "foo"
],
cmw_record_bytes().as_slice(),
        ].concat()
    }

    fn timestamp() -> TimeStamp {
        DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
            .unwrap()
            .into()
    }

    #[rustfmt::skip]
    fn timestamp_bytes() -> Vec<u8> {
        vec![
0xC0, // tag(0)
    0x74, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x39, 0x2D, 0x30, 0x34, 0x54, 0x31, 0x33, 0x3A, 0x30, 0x34, 0x3A, 0x33, 0x39, 0x5A, // "2020-09-04T13:04:39Z"
        ]
    }

    #[test]
    fn test_cmw_wrapper() {
        let record = get_cmw_record();
        let collection = get_cmw_collection();

        let record_cbor = record.marshal_cbor().unwrap();
        let collection_cbor = collection.marshal_cbor().unwrap();

        let tests: Vec<(CmwCborType, Vec<u8>)> = vec![
            (CmwCborType(Cow::Owned(record)), record_cbor),
            (CmwCborType(Cow::Owned(collection)), collection_cbor),
        ];
        for (i, (val, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&val, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {val:?}");

            let val_de: CmwCborType = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(*val, val_de, "de at index {i}: {val:?} != {val_de:?}");
        }
    }

    #[test]
    fn test_reference_values_quad() {
        let tests: Vec<(ReferenceValuesQuad, Vec<u8>)> = vec![(rv_quad(), rv_quad_bytes())];
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
        let tests: Vec<(EndorsedValuesQuad, Vec<u8>)> = vec![(ev_quad(), ev_quad_bytes())];

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
        let tests: Vec<(ConditionalEndorsementQuad, Vec<u8>)> =
            vec![(cev_quad(), cev_quad_bytes())];

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
        let tests: Vec<(AttestKeyQuad, Vec<u8>)> = vec![(ak_quad(), ak_quad_bytes())];
        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
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
        let cmw = get_cmw_record();

        #[rustfmt::skip]
        let tests: Vec<(CoservResult, Vec<u8>)> = vec![
            (
                CoservResult {
                    result_set: Some(ResultSetTypeChoice::ReferenceValues(
                        ReferenceValuesResult {
                            rv_quads: vec![rv_quad()]
                        },
                    )),
                    expiry: timestamp(),
                    source_artifacts: None,
                    rim_result: None,
                },
                [
&[
0xa2, // map(2)
    0x00, // unsigned(0) rvq
    0x81, // array(1) ([rvq])
],
        rv_quad_bytes().as_slice(),
&[
    0x0a, // unsigned(10) expiry
],
        timestamp_bytes().as_slice(),

].concat()
            ),

            (
                CoservResult {
                    result_set: Some(ResultSetTypeChoice::TrustAnchors(
                        TrustAnchorsResult {
                            ak_quads: vec![ak_quad()]
                        }
                    )),
                    expiry: timestamp(),
                    source_artifacts: None,
                    rim_result: None,
                },
                [
&[
0xA3, // map(3)
    0x03, // key 3 akq
        0x81, // array(1)
],
            ak_quad_bytes().as_slice(),
&[
    0x04, // key 4 cots-stmt
        0x80, // array(0)
    0x0A, // key 10 expiry
],
        timestamp_bytes().as_slice()
].concat(),
            ),
            (
                CoservResult {
                    result_set: Some(ResultSetTypeChoice::ReferenceValues(
                        ReferenceValuesResult {
                            rv_quads: vec![rv_quad()]
                        },
                    )),
                    expiry: timestamp(),
                    source_artifacts: Some(vec![cmw]),
                    rim_result: None,
                },
                [
&[
0xa3, // map(3)
    0x00, // unsigned(0) rvq
        0x81, // array(1)
],
            rv_quad_bytes().as_slice(),
&[
    0x0a, // unsigned(10) expiry
],
        timestamp_bytes().as_slice(),
&[
    0x0b, // unsigned(11) source-artifacts
        0x81, // array(1)
],
            cmw_record_bytes().as_slice(),
                ].concat(),
            ),
            (
                CoservResult {
                    expiry: timestamp(),
                    rim_result: get_cmw_collection().into(),
                    result_set: None,
                    source_artifacts: None,
                },
                [
&[
0xA2, // map(2)
    0x05, // key 5 rim-results
],
        cmw_collection_bytes().as_slice(),
&[
    0x0A, // key 10
],
        timestamp_bytes().as_slice(),
                ].concat(),
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
    fn test_coserv_result_set_builder_public() {
        let empty_result = ResultSetBuilder::new().build();
        assert!(empty_result.is_err());

        let rv_result = ResultSetBuilder::new().rvq(vec![rv_quad()]).build();
        assert!(rv_result.is_ok());

        let ev_result = ResultSetBuilder::new().evq(vec![ev_quad()]).build();
        assert!(ev_result.is_ok());

        let cev_result = ResultSetBuilder::new().ceq(vec![cev_quad()]).build();
        assert!(cev_result.is_ok());

        let endorsed_values_both = ResultSetBuilder::new()
            .ceq(vec![cev_quad()])
            .evq(vec![ev_quad()])
            .build();
        assert!(endorsed_values_both.is_ok());

        let ta_result = ResultSetBuilder::new().akq(vec![ak_quad()]).build();
        assert!(ta_result.is_ok());

        let ta_rv_res = ResultSetBuilder::new()
            .akq(vec![ak_quad()])
            .rvq(vec![rv_quad()])
            .build();
        assert!(ta_rv_res.is_err());

        let ta_ev_res = ResultSetBuilder::new()
            .akq(vec![ak_quad()])
            .evq(vec![ev_quad()])
            .build();
        assert!(ta_ev_res.is_err());

        let rv_ev_res = ResultSetBuilder::new()
            .rvq(vec![rv_quad()])
            .ceq(vec![cev_quad()])
            .build();
        assert!(rv_ev_res.is_err());
    }

    #[test]
    fn test_coserv_result_set_builder_public_add_quads() {
        let mut builder = ResultSetBuilder::new();
        builder.add_akq(ak_quad());
        builder.add_akq(ak_quad());
        assert_eq!(builder.akq, Some(vec![ak_quad(), ak_quad()]));
        assert!(builder.build().is_ok());

        let mut builder = ResultSetBuilder::new();
        builder.add_rvq(rv_quad());
        let res = builder.build();
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            ResultSetTypeChoice::ReferenceValues(ReferenceValuesResult {
                rv_quads: vec![rv_quad()]
            })
        );

        let mut builder = ResultSetBuilder::new();
        builder.add_evq(ev_quad());
        builder.add_evq(ev_quad());
        builder.add_ceq(cev_quad());
        let res = builder.build();
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            ResultSetTypeChoice::EndorsedValues(EndorsedValuesResult {
                ev_quads: vec![ev_quad(), ev_quad()],
                cev_quads: vec![cev_quad()],
            })
        );
    }

    #[test]
    fn test_coserv_result_set_builder_internal() {
        let empty_result = ResultSetBuilder::new().deserializer_build();
        assert!(empty_result.is_ok());

        let mut rv_res = ResultSetBuilder::new();
        rv_res.set_rvq(vec![rv_quad()]);
        assert!(rv_res.deserializer_build().is_ok());

        let mut partial_ev1 = ResultSetBuilder::new();
        partial_ev1.set_evq(vec![ev_quad()]);
        assert!(partial_ev1.deserializer_build().is_err());

        let mut partial_ev2 = ResultSetBuilder::new();
        partial_ev2.set_ceq(vec![cev_quad()]);
        assert!(partial_ev2.deserializer_build().is_err());

        let mut ev_res = ResultSetBuilder::new();
        ev_res.set_evq(vec![ev_quad()]);
        ev_res.set_ceq(vec![cev_quad()]);
        assert!(ev_res.deserializer_build().is_ok());

        let mut partial_ta_res = ResultSetBuilder::new();
        partial_ta_res.set_akq(vec![ak_quad()]);
        assert!(partial_ta_res.deserializer_build().is_err());

        let mut ta_res = ResultSetBuilder::new();
        ta_res.set_akq(vec![ak_quad()]);
        ta_res.set_cots();
        assert!(ta_res.deserializer_build().is_ok());

        let mut ta_rv = ResultSetBuilder::new();
        ta_rv.set_akq(vec![ak_quad()]);
        ta_rv.set_rvq(vec![rv_quad()]);
        assert!(ta_rv.build().is_err());

        let mut ta_ev = ResultSetBuilder::new();
        ta_ev.set_evq(vec![ev_quad()]);
        ta_ev.set_ceq(vec![cev_quad()]);
        ta_ev.set_akq(vec![ak_quad()]);
        assert!(ta_ev.build().is_err());
    }

    #[test]
    fn test_coserv_result_builder() {
        let cmw = get_cmw_record();

        // result set contains only source artifiacts
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .source_artifacts(vec![cmw.clone()]);
        assert!(builder.build().is_ok());

        let builder = CoservResultBuilder::new();
        let err = builder.build();
        assert!(err.is_err());

        let mut builder = CoservResultBuilder::new();
        builder = builder.expiry(timestamp());
        let err = builder.build();
        assert!(err.is_ok());

        // result set contains both source and collected artifacts
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .source_artifacts(vec![cmw.clone()])
            .result_set(ResultSetTypeChoice::ReferenceValues(
                ReferenceValuesResult {
                    rv_quads: vec![rv_quad()],
                },
            ));
        assert!(builder.build().is_ok());

        // result set contains source artifacts but not all of them are monads (invalid)
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .source_artifacts(vec![cmw.clone(), get_cmw_collection()]);
        assert!(builder.build().is_err());

        // result contains rim results only
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .rim_result(get_cmw_collection());
        assert!(builder.build().is_ok());

        // result contains rim results, but a cmw monad (invalid)
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .rim_result(get_cmw_record());
        assert!(builder.build().is_err());

        // result contains both rim and env result (invalid)
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .rim_result(get_cmw_collection())
            .result_set(ResultSetTypeChoice::ReferenceValues(
                ReferenceValuesResult {
                    rv_quads: vec![rv_quad()],
                },
            ));
        assert!(builder.build().is_err());

        // result contains both rim results and source artifacts (invalid)
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .rim_result(get_cmw_collection())
            .source_artifacts(vec![get_cmw_collection()]);
        assert!(builder.build().is_err());

        // result contains empty array as source artifacts
        let builder = CoservResultBuilder::new()
            .expiry(timestamp())
            .source_artifacts(vec![]);
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_empty_result_predicate() {
        let builder = CoservResultBuilder::new().expiry(timestamp());
        let empty_rs = ResultSetBuilder::new().rvq(Vec::new()).build().unwrap();
        let non_empty_rs = ResultSetBuilder::new()
            .rvq(vec![rv_quad()])
            .build()
            .unwrap();
        let empty = [
            builder.clone().build().unwrap(),
            builder
                .clone()
                .result_set(empty_rs.clone())
                .build()
                .unwrap(),
        ];
        for (i, rs) in empty.iter().enumerate() {
            assert!(rs.is_empty(), "empty check failed at index {i}: {rs:?}");
        }

        let non_empty = [
            builder.clone().result_set(non_empty_rs).build().unwrap(),
            builder
                .clone()
                .rim_result(get_cmw_collection())
                .build()
                .unwrap(),
            builder
                .clone()
                .source_artifacts(vec![get_cmw_record()])
                .build()
                .unwrap(),
            builder
                .clone()
                .result_set(empty_rs.clone())
                .source_artifacts(vec![get_cmw_record()])
                .build()
                .unwrap(),
        ];
        for (i, rs) in non_empty.iter().enumerate() {
            assert!(
                !rs.is_empty(),
                "non-empty check failed at index {i}: {rs:?}"
            );
        }
    }

    fn rv_quad() -> ReferenceValuesQuad<'static> {
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
                    mval: m1(),
                    authorized_by: None,
                }],
            },
        }
    }

    #[rustfmt::skip]
    fn rv_quad_bytes() -> Vec<u8> {
        [
&[
0xa2, // map(2)
    0x01, // unsigned(1) authorities
    0x82, // array(2)
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
    0x02, // unsigned(2) triple
    0x82, // array(2)
        0xa1, // map(1) ref-env
            0x01, // unsigned(1)
            0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0x81, // array(1) ref-claims
],
            m1_bytes().as_slice(),
        ].concat()

    }

    fn ev_quad() -> EndorsedValuesQuad<'static> {
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
                    mval: m1(),
                    authorized_by: None,
                }],
            },
        }
    }

    #[rustfmt::skip]
    fn ev_quad_bytes() -> Vec<u8> {
        [&[
0xa2, // map(2)
    0x01, // unsigned(1) authorities
    0x82, // array(2)
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
    0x02, // unsigned(2) triple
    0x82, // array(2)
        0xa1, // map(1) condition (environment-map)
            0x01, // unsigned(1)
            0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0x81, // array(1) endorsement ([measurement-map])
    ],
    m1_bytes().as_slice()
    ].concat()
    }

    fn cev_quad() -> ConditionalEndorsementQuad<'static> {
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
                        mval: m1(),
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
                        mval: m2(),
                        authorized_by: None,
                    }],
                }],
            },
        }
    }

    #[rustfmt::skip]
    fn cev_quad_bytes() -> Vec<u8> {
        [
&[
0xa2, // map(2) authorities
    0x01, // unsigned(1)
    0x82, // array(2)
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
    0x02, // unsigned(2) // triple
    0x82, // array(2)
        0x81, // array(1) conditions
            0x82, // array(2) stateful-environment
                0xa1, // map(1) environment map
                    0x01, // unsigned(1)
                    0xd9, 0x02, 0x30, // tag(560)
                        0x44, // bytes(4)
                        0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x81, // array(1) claims-list ([measurement-map])
],
                    m1_bytes().as_slice(),
&[
        0x81, // array(1) endorsements
        0x82, // array(2) endorsed-triple-record
            0xa1, // map(1) environment-map
                0x01, // unsigned(1)
                0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
            0x81, // array(1) endorsement ([measurement-map])
],
                m2_bytes().as_slice(),
].concat()
    }

    fn ak_quad() -> AttestKeyQuad<'static> {
        AttestKeyQuad {
            authorities: vec![
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                CryptoKeyTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
            ],
            triple: AttestKeyTripleRecord {
                environment: env1(),
                key_list: vec![CryptoKeyTypeChoice::Bytes(
                    Bytes::from(vec![1, 2, 3, 4]).into(),
                )],
                conditions: Some(TriplesRecordCondition {
                    mkey: Some("foo".into()),
                    authorized_by: None,
                }),
            },
        }
    }

    #[rustfmt::skip]
    fn ak_quad_bytes() -> Vec<u8> {
        [
&[
0xa2, // map(2)
    0x01, // unsigned(1) authorities
        0x82, // array(2)
            0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
            0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
    0x02, // unsigned(2) triple
    0x83, // array(3)
],
        env1_bytes().as_slice(),
&[
        0x81, // array(1) key-list
            0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        0xa1, // map(1) conditions
            0x00, // unsigned(0) mkey
            0x63, // text(3)
            0x66, 0x6f, 0x6f, // "foo"
]
    ].concat()
    }

    fn env1() -> EnvironmentMap<'static> {
        EnvironmentMapBuilder::new()
            .instance(InstanceIdTypeChoice::Bytes(
                Bytes::from(vec![1, 2, 3, 4]).into(),
            ))
            .build()
            .unwrap()
    }

    #[rustfmt::skip]
    fn env1_bytes()  -> Vec<u8> {
        vec![
0xa1, // map(1)
    0x01, // unsigned(1) instance
    0xd9, 0x02, 0x30, // tag(560) tagged bytes
        0x44, // bytes(4)
        0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
        ]
    }

    #[allow(unused)]
    fn env2() -> EnvironmentMap<'static> {
        EnvironmentMapBuilder::new()
            .instance(InstanceIdTypeChoice::Bytes(
                Bytes::from(vec![2, 3, 4, 5]).into(),
            ))
            .build()
            .unwrap()
    }

    #[rustfmt::skip]
    #[allow(unused)]
   fn env2_bytes()  -> Vec<u8> {
        vec![
0xa1, // map(1)
    0x01, // unsigned(1) instance
    0xd9, 0x02, 0x30, // tag(560) tagged bytes
        0x44, // bytes(4)
        0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
        ]
    }

    fn m1() -> MeasurementValuesMap<'static> {
        MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        }
    }

    #[rustfmt::skip]
    fn m1_bytes() -> Vec<u8> {
        vec![
0xa1, // map(1)
    0x01, // unsigned(1)
    0xa1, // map(1)
        0x0b, // unsigned(11)
        0x63, // text(3)
        0x66, 0x6f, 0x6f, // "foo"
        ]
    }

    fn m2() -> MeasurementValuesMap<'static> {
        MeasurementValuesMap {
            name: Some("bar".into()),
            ..Default::default()
        }
    }

    #[rustfmt::skip]
    fn m2_bytes() -> Vec<u8> {
        vec![
0xa1, // map(1)
    0x01, // unsigned(1)
    0xa1, // map(1)
        0x0b, // unsigned(11)
        0x63, // text(3)
        0x62, 0x61, 0x72, // "bar"
        ]
    }
}
