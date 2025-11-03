// SPDX-License-Identifier: Apache-2.0

use super::common::TimeStamp;
use crate::error::CoservError;
use corim_rs::triples::{ClassMap, GroupIdTypeChoice, InstanceIdTypeChoice, MeasurementMap};
use serde::{
    de::{self, Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor},
    ser::{Serialize, SerializeMap, SerializeSeq, Serializer},
};
use std::fmt;
use std::marker::PhantomData;

/// Representation of CoSERV query map.
/// Use [QueryBuilder] to build this struct.
#[derive(Debug, PartialEq)]
pub struct Query<'a> {
    /// Query artifact type
    pub artifact_type: ArtifactTypeChoice,
    /// environment selector map
    pub environment_selector: EnvironmentSelectorMap<'a>,
    /// timestamp of query
    pub timestamp: TimeStamp,
    /// result type selector
    pub result_type: ResultTypeChoice,
}

/// Builder for [Query]
#[derive(Debug, Default)]
pub struct QueryBuilder<'a> {
    pub artifact_type: Option<ArtifactTypeChoice>,
    pub environment_selector: Option<EnvironmentSelectorMap<'a>>,
    pub timestamp: Option<TimeStamp>,
    pub result_type: Option<ResultTypeChoice>,
}

impl<'a> QueryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn artifact_type(mut self, value: ArtifactTypeChoice) -> Self {
        self.artifact_type = Some(value);
        self
    }

    pub fn environment_selector(mut self, value: EnvironmentSelectorMap<'a>) -> Self {
        self.environment_selector = Some(value);
        self
    }

    // this function is used only by the deserializer.
    // While building, this should be set to `now`
    fn timestamp(mut self, value: TimeStamp) -> Self {
        self.timestamp = Some(value);
        self
    }

    pub fn result_type(mut self, value: ResultTypeChoice) -> Self {
        self.result_type = Some(value);
        self
    }

    pub fn build(self) -> Result<Query<'a>, CoservError> {
        Ok(Query {
            artifact_type: self.artifact_type.ok_or(CoservError::RequiredFieldNotSet(
                "artifact type".into(),
                "query".into(),
            ))?,
            environment_selector: self.environment_selector.ok_or(
                CoservError::RequiredFieldNotSet("environment selector".into(), "query".into()),
            )?,
            timestamp: self.timestamp.unwrap_or(TimeStamp::now()),
            result_type: self.result_type.ok_or(CoservError::RequiredFieldNotSet(
                "result type".into(),
                "query".into(),
            ))?,
        })
    }
}

impl Serialize for Query<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&0, &self.artifact_type)?;
        map.serialize_entry(&1, &self.environment_selector)?;
        map.serialize_entry(&2, &self.timestamp)?;
        map.serialize_entry(&3, &self.result_type)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Query<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct QueryVisitor<'a> {
            marker: PhantomData<&'a str>,
        }
        impl<'de, 'a> Visitor<'de> for QueryVisitor<'a> {
            type Value = Query<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "map containing CoSERV query (Query)")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut builder = QueryBuilder::new();
                loop {
                    match access.next_key::<i64>()? {
                        Some(0) => {
                            builder =
                                builder.artifact_type(access.next_value::<ArtifactTypeChoice>()?);
                        }
                        Some(1) => {
                            builder = builder.environment_selector(
                                access.next_value::<EnvironmentSelectorMap<'a>>()?,
                            );
                        }
                        Some(2) => {
                            builder = builder.timestamp(access.next_value::<TimeStamp>()?);
                        }
                        Some(3) => {
                            builder = builder.result_type(access.next_value::<ResultTypeChoice>()?);
                        }
                        Some(n) => Err(de::Error::unknown_field(
                            n.to_string().as_str(),
                            &["0", "1", "2", "3"],
                        ))?,
                        None => break,
                    };
                }
                // decoded query without timestamp is invalid
                if builder.timestamp.is_none() {
                    return Err(M::Error::custom(
                        "Required field timestamp not present in query",
                    ));
                }
                builder.build().map_err(M::Error::custom)
            }
        }

        deserializer.deserialize_map(QueryVisitor {
            marker: PhantomData,
        })
    }
}

/// artifact type queried
#[derive(Debug, PartialEq)]
pub enum ArtifactTypeChoice {
    EndorsedValues,
    TrustAnchors,
    ReferenceValues,
}

impl From<&ArtifactTypeChoice> for i64 {
    fn from(value: &ArtifactTypeChoice) -> Self {
        match value {
            ArtifactTypeChoice::EndorsedValues => 0,
            ArtifactTypeChoice::TrustAnchors => 1,
            ArtifactTypeChoice::ReferenceValues => 2,
        }
    }
}

impl TryFrom<i64> for ArtifactTypeChoice {
    type Error = &'static str;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ArtifactTypeChoice::EndorsedValues),
            1 => Ok(ArtifactTypeChoice::TrustAnchors),
            2 => Ok(ArtifactTypeChoice::ReferenceValues),
            _ => Err("unknown field for artifact type"),
        }
    }
}

impl Serialize for ArtifactTypeChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.into())
    }
}

impl<'de> Deserialize<'de> for ArtifactTypeChoice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        i64::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

/// Environment selector for query
/// Can be either class-based or instance-based or group-based.
#[derive(Debug, PartialEq)]
pub enum EnvironmentSelectorMap<'a> {
    Class(Vec<StatefulClass<'a>>),
    Instance(Vec<StatefulInstance<'a>>),
    Group(Vec<StatefulGroup<'a>>),
}

impl Serialize for EnvironmentSelectorMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            EnvironmentSelectorMap::Class(cl) => map.serialize_entry(&0, cl),
            EnvironmentSelectorMap::Instance(inst) => map.serialize_entry(&1, inst),
            EnvironmentSelectorMap::Group(grp) => map.serialize_entry(&2, grp),
        }?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for EnvironmentSelectorMap<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnvironmentSelectorMapVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for EnvironmentSelectorMapVisitor<'a> {
            type Value = EnvironmentSelectorMap<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "CoSERV environment selector map")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                match access.next_key::<i64>()? {
                    Some(0) => Ok(Self::Value::Class(
                        access.next_value::<Vec<StatefulClass<'a>>>()?,
                    )),
                    Some(1) => Ok(Self::Value::Instance(
                        access.next_value::<Vec<StatefulInstance<'a>>>()?,
                    )),
                    Some(2) => Ok(Self::Value::Group(
                        access.next_value::<Vec<StatefulGroup<'a>>>()?,
                    )),
                    Some(n) => Err(M::Error::unknown_field(
                        n.to_string().as_str(),
                        &["0", "1", "2"],
                    )),
                    None => Err(M::Error::custom("malformed environment selector map")),
                }
            }
        }
        deserializer.deserialize_map(EnvironmentSelectorMapVisitor {
            marker: PhantomData,
        })
    }
}

/// representation of stateful class.
/// Use [StatefulClassBuilder] to build this.
pub type StatefulClass<'a> = StatefulEnvironment<'a, ClassMap<'a>>;

/// representation of stateful instance
/// Use [StatefulInstanceBuilder] to build this.
pub type StatefulInstance<'a> = StatefulEnvironment<'a, InstanceIdTypeChoice<'a>>;

/// representation of stateful group
/// Use [StatefulGroupBuilder] to build this.
pub type StatefulGroup<'a> = StatefulEnvironment<'a, GroupIdTypeChoice<'a>>;

/// builder for [StatefulClass]
pub type StatefulClassBuilder<'a> = StatefulEnvironmentBuilder<'a, ClassMap<'a>>;

/// builder for [StatefulInstance]
pub type StatefulInstanceBuilder<'a> = StatefulEnvironmentBuilder<'a, InstanceIdTypeChoice<'a>>;

/// builder for [StatefulGroup]
pub type StatefulGroupBuilder<'a> = StatefulEnvironmentBuilder<'a, GroupIdTypeChoice<'a>>;

// empty private trait that should be implemented for
// valid environments in coserv
trait AcceptedCoservEnvironment {}

impl AcceptedCoservEnvironment for ClassMap<'_> {}
impl AcceptedCoservEnvironment for InstanceIdTypeChoice<'_> {}
impl AcceptedCoservEnvironment for GroupIdTypeChoice<'_> {}

/// Generic object for stateful environment.
/// Use [StatefulClass], [StatefulInstance], [StatefulGroup]
/// instead of this.
///
/// Note: definitions of this cannot be made outside of this
/// crate because of private bounds on T
#[allow(private_bounds)]
#[derive(Debug, PartialEq)]
pub struct StatefulEnvironment<'a, T>
where
    T: Serialize + AcceptedCoservEnvironment,
{
    /// environment
    pub environment: T,
    /// state
    pub measurements: Option<Vec<MeasurementMap<'a>>>,
}

/// Builder for [StatefulEnvironment].
/// Use [StatefulClassBuilder], [StatefulInstanceBuilder], [StatefulGroupBuilder]
/// instead of this.
#[derive(Debug)]
#[allow(private_bounds)]
pub struct StatefulEnvironmentBuilder<'a, T>
where
    T: Serialize + AcceptedCoservEnvironment,
{
    environment: Option<T>,
    measurements: Option<Vec<MeasurementMap<'a>>>,
}

impl<T> Default for StatefulEnvironmentBuilder<'_, T>
where
    T: Serialize + AcceptedCoservEnvironment,
{
    fn default() -> Self {
        StatefulEnvironmentBuilder {
            environment: None,
            measurements: None,
        }
    }
}

#[allow(private_bounds)]
impl<'a, T> StatefulEnvironmentBuilder<'a, T>
where
    T: Serialize + AcceptedCoservEnvironment,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn environment(mut self, value: T) -> Self {
        self.environment = Some(value);
        self
    }

    pub fn add_measurement(mut self, value: MeasurementMap<'a>) -> Self {
        if let Some(ref mut v) = self.measurements {
            v.push(value);
        } else {
            self.measurements = Some(vec![value]);
        }
        self
    }

    pub fn measurements(mut self, value: Vec<MeasurementMap<'a>>) -> Self {
        self.measurements = Some(value);
        self
    }

    pub fn build(self) -> Result<StatefulEnvironment<'a, T>, CoservError> {
        if self.environment.is_none() {
            return Err(CoservError::RequiredFieldNotSet(
                "environment".into(),
                "stateful environment".into(),
            ));
        }
        Ok(StatefulEnvironment {
            environment: self.environment.ok_or(CoservError::RequiredFieldNotSet(
                "environment".into(),
                "stateful environment".into(),
            ))?,
            measurements: self.measurements,
        })
    }
}

impl<T> Serialize for StatefulEnvironment<'_, T>
where
    T: Serialize + AcceptedCoservEnvironment,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // should not use indefinite length encoding
        let num_elts = 1 +  // environment
            self.measurements.is_some() as usize; // measurements
        let mut seq = serializer.serialize_seq(Some(num_elts))?;
        seq.serialize_element(&self.environment)?;
        if let Some(meas) = &self.measurements {
            seq.serialize_element(meas)?;
        }
        seq.end()
    }
}

impl<'a, 'de, T> Deserialize<'de> for StatefulEnvironment<'a, T>
where
    T: Deserialize<'de> + Serialize + AcceptedCoservEnvironment + 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(StatefulEnvVisitor::<'a, T> {
            marker: PhantomData,
        })
    }
}

struct StatefulEnvVisitor<'a, T> {
    marker: PhantomData<&'a T>,
}

impl<'de, 'a, T> Visitor<'de> for StatefulEnvVisitor<'a, T>
where
    T: Serialize + Deserialize<'de> + AcceptedCoservEnvironment + 'a,
{
    type Value = StatefulEnvironment<'a, T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "CoSERV stateful environment")
    }

    fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut builder = StatefulEnvironmentBuilder::new();
        let env = access
            .next_element::<T>()?
            .ok_or(S::Error::custom("environment identifier cannot be empty"))?;
        builder = builder.environment(env);
        if let Some(meas) = access.next_element::<Vec<MeasurementMap<'a>>>()? {
            builder = builder.measurements(meas);
        }
        builder.build().map_err(S::Error::custom)
    }
}

/// Result type queried: source artifacts, collected artifacts
/// or both
#[derive(Debug, PartialEq)]
pub enum ResultTypeChoice {
    CollectedArtifacts,
    SourceArtifacts,
    Both,
}

impl From<&ResultTypeChoice> for i64 {
    fn from(value: &ResultTypeChoice) -> Self {
        match value {
            ResultTypeChoice::CollectedArtifacts => 0,
            ResultTypeChoice::SourceArtifacts => 1,
            ResultTypeChoice::Both => 2,
        }
    }
}

impl TryFrom<i64> for ResultTypeChoice {
    type Error = &'static str;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ResultTypeChoice::CollectedArtifacts),
            1 => Ok(ResultTypeChoice::SourceArtifacts),
            2 => Ok(ResultTypeChoice::Both),
            _ => Err("unknown field"),
        }
    }
}

impl Serialize for ResultTypeChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.into())
    }
}

impl<'de> Deserialize<'de> for ResultTypeChoice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        i64::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use corim_rs::triples::MeasurementValuesMap;
    use corim_rs::{Bytes, ClassIdTypeChoice};
    #[test]
    fn test_artifact_type_choice() {
        let tests: Vec<(ArtifactTypeChoice, Vec<u8>)> = vec![
            (ArtifactTypeChoice::EndorsedValues, vec![0x00]),
            (ArtifactTypeChoice::TrustAnchors, vec![0x01]),
            (ArtifactTypeChoice::ReferenceValues, vec![0x02]),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: ArtifactTypeChoice =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        assert!(ArtifactTypeChoice::try_from(3).is_err());
    }

    #[test]
    fn test_result_type_choice() {
        let tests: Vec<(ResultTypeChoice, Vec<u8>)> = vec![
            (ResultTypeChoice::CollectedArtifacts, vec![0x00]),
            (ResultTypeChoice::SourceArtifacts, vec![0x01]),
            (ResultTypeChoice::Both, vec![0x02]),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: ResultTypeChoice = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<ResultTypeChoice, _> = ciborium::from_reader([0x03_u8].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_stateful_class() {
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
        let tests: Vec<(StatefulClass, Vec<u8>)> = vec![
            (
                StatefulClass {
                    environment: ClassMap {
                        class_id: Some(ClassIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        vendor: None,
                        model: None,
                        layer: None,
                        index: None,
                    },
                    measurements: None,
                },
                vec![
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x00, // unsigned(0)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04,
                ],
            ),
            (
                StatefulClass {
                    environment: ClassMap {
                        class_id: Some(ClassIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        )),
                        vendor: None,
                        model: None,
                        layer: None,
                        index: None,
                    },
                    measurements: Some(vec![
                        MeasurementMap {
                            mkey: None,
                            mval: m1,
                            authorized_by: None,
                        },
                        MeasurementMap {
                            mkey: None,
                            mval: m2,
                            authorized_by: None,
                        },
                    ]),
                },
                vec![
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x00, // unsigned(0)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, 0x82, // array(2)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, 0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x62, 0x61, 0x72,
                ],
            ),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: StatefulClass = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<StatefulClass, _> = ciborium::from_reader([0x80_u8].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_stateful_instance() {
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
        let tests: Vec<(StatefulInstance, Vec<u8>)> = vec![
            (
                StatefulInstance {
                    environment: InstanceIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    measurements: None,
                },
                vec![
                    0x81, // array(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                ],
            ),
            (
                StatefulInstance {
                    environment: InstanceIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    measurements: Some(vec![
                        MeasurementMap {
                            mkey: None,
                            mval: m1,
                            authorized_by: None,
                        },
                        MeasurementMap {
                            mkey: None,
                            mval: m2,
                            authorized_by: None,
                        },
                    ]),
                },
                vec![
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x62, 0x61, 0x72, // "bar"
                ],
            ),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: StatefulInstance = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<StatefulInstance, _> = ciborium::from_reader([0x80_u8].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_stateful_group() {
        // redundant
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
        let tests: Vec<(StatefulGroup, Vec<u8>)> = vec![
            (
                StatefulGroup {
                    environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    measurements: None,
                },
                vec![
                    0x81, // array(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                ],
            ),
            (
                StatefulGroup {
                    environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                    measurements: Some(vec![
                        MeasurementMap {
                            mkey: None,
                            mval: m1,
                            authorized_by: None,
                        },
                        MeasurementMap {
                            mkey: None,
                            mval: m2,
                            authorized_by: None,
                        },
                    ]),
                },
                vec![
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x62, 0x61, 0x72, // "bar"
                ],
            ),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: StatefulGroup = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<StatefulGroup, _> = ciborium::from_reader([0x80_u8].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_environment_selector_map() {
        let m1 = MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        };
        let tests: Vec<(EnvironmentSelectorMap, Vec<u8>)> = vec![
            (
                EnvironmentSelectorMap::Class(vec![
                    StatefulClass {
                        environment: ClassMap {
                            class_id: Some(ClassIdTypeChoice::Bytes(
                                Bytes::from(vec![1, 2, 3, 4]).into(),
                            )),
                            vendor: None,
                            model: None,
                            layer: None,
                            index: None,
                        },
                        measurements: None,
                    },
                    StatefulClass {
                        environment: ClassMap {
                            class_id: Some(ClassIdTypeChoice::Bytes(
                                Bytes::from(vec![2, 3, 4, 5]).into(),
                            )),
                            vendor: None,
                            model: None,
                            layer: None,
                            index: None,
                        },
                        measurements: Some(vec![MeasurementMap {
                            mkey: None,
                            mval: m1.clone(),
                            authorized_by: None,
                        }]),
                    },
                ]),
                vec![
                    0xa1, // map(1)
                    0x00, // unsigned(0)
                    0x82, // array(2)
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x00, // unsigned(0)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x82, // array(2)
                    0xa1, // map(1)
                    0x00, // unsigned(0)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x02, 0x03, 0x04, 0x05, // "\u0001\u0002\u0003\u0004"
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                ],
            ),
            (
                EnvironmentSelectorMap::Instance(vec![
                    StatefulInstance {
                        environment: InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![1, 2, 3, 4]).into(),
                        ),
                        measurements: None,
                    },
                    StatefulInstance {
                        environment: InstanceIdTypeChoice::Bytes(
                            Bytes::from(vec![2, 3, 4, 5]).into(),
                        ),
                        measurements: Some(vec![MeasurementMap {
                            mkey: None,
                            mval: m1.clone(),
                            authorized_by: None,
                        }]),
                    },
                ]),
                vec![
                    0xa1, // map(1)
                    0x01, // unsigned(0)
                    0x82, // array(2)
                    0x81, // array(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                ],
            ),
            (
                EnvironmentSelectorMap::Group(vec![
                    StatefulGroup {
                        environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                        measurements: None,
                    },
                    StatefulGroup {
                        environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                        measurements: Some(vec![MeasurementMap {
                            mkey: None,
                            mval: m1.clone(),
                            authorized_by: None,
                        }]),
                    },
                ]),
                vec![
                    0xa1, // map(1)
                    0x02, // unsigned(0)
                    0x82, // array(2)
                    0x81, // array(1)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                    0x82, // array(2)
                    0xd9, 0x02, 0x30, // tag(560)
                    0x44, // bytes(4)
                    0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                    0x81, // array(1)
                    0xa1, // map(1)
                    0x01, // unsigned(1)
                    0xa1, // map(1)
                    0x0b, // unsigned(11)
                    0x63, // text(3)
                    0x66, 0x6f, 0x6f, // "foo"
                ],
            ),
        ];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: EnvironmentSelectorMap =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let err: Result<EnvironmentSelectorMap, _> = ciborium::from_reader([0xa0_u8].as_slice());
        assert!(err.is_err());

        let err: Result<EnvironmentSelectorMap, _> =
            ciborium::from_reader([0xa1, 0x03, 0x80].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_query() {
        let m1 = MeasurementValuesMap {
            name: Some("foo".into()),
            ..Default::default()
        };
        let tests: Vec<(Query, Vec<u8>)> = vec![(
            Query {
                artifact_type: ArtifactTypeChoice::ReferenceValues,
                environment_selector: EnvironmentSelectorMap::Group(vec![
                    StatefulGroup {
                        environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]).into()),
                        measurements: None,
                    },
                    StatefulGroup {
                        environment: GroupIdTypeChoice::Bytes(Bytes::from(vec![2, 3, 4, 5]).into()),
                        measurements: Some(vec![MeasurementMap {
                            mkey: None,
                            mval: m1.clone(),
                            authorized_by: None,
                        }]),
                    },
                ]),
                timestamp: DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z")
                    .unwrap()
                    .into(),
                result_type: ResultTypeChoice::CollectedArtifacts,
            },
            vec![
                0xa4, // map(4)
                0x00, // unsigned(0)
                0x02, // unsigned(2)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x02, // unsigned(2)
                0x82, // array(2)
                0x81, // array(1)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x82, // array(2)
                0xd9, 0x02, 0x30, // tag(560)
                0x44, // bytes(4)
                0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
                0x81, // array(1)
                0xa1, // map(1)
                0x01, // unsigned(1)
                0xa1, // map(1)
                0x0b, // unsigned(11)
                0x63, // text(3)
                0x66, 0x6f, 0x6f, // "foo"
                0x02, // unsigned(2)
                0xc0, 0x74, // text(20)
                0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33, 0x3a,
                0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a, // "2020-09-04T13:04:39Z"
                0x03, // unsigned(3)
                0x00, // unsigned(0)
            ],
        )];

        for (i, (value, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&value, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {value:?}");

            let value_de: Query = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(
                *value, value_de,
                "de at index {i}: {value:?} != {value_de:?}"
            );
        }

        let cbor_invalid_key: Vec<u8> = vec![0xa1, 0x04, 0x80];
        let err: Result<Query, _> = ciborium::from_reader(cbor_invalid_key.as_slice());
        assert!(err.is_err());

        let cbor_missing_timestamp: Vec<u8> = vec![
            0xa3, // map(3)
            0x00, // unsigned(0)
            0x02, // unsigned(2)
            0x01, // unsigned(1)
            0xa1, // map(1)
            0x02, // unsigned(2)
            0x82, // array(2)
            0x81, // array(1)
            0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
            0x82, // array(2)
            0xd9, 0x02, 0x30, // tag(560)
            0x44, // bytes(4)
            0x02, 0x03, 0x04, 0x05, // "\u0002\u0003\u0004\u0005"
            0x81, // array(1)
            0xa1, // map(1)
            0x01, // unsigned(1)
            0xa1, // map(1)
            0x0b, // unsigned(11)
            0x63, // text(3)
            0x66, 0x6f, 0x6f, // "foo"
            0x03, // unsigned(3)
            0x00, // unsigned(0)
        ];
        let err: Result<Query, _> = ciborium::from_reader(cbor_missing_timestamp.as_slice());
        assert!(err.is_err());
    }
}
