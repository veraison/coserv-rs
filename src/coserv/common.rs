// SPDX-License-Identifier: Apache-2.0

use chrono::{format::SecondsFormat, DateTime, FixedOffset, Local};
use corim_rs::generate_tagged;
use derive_more::From;
use std::ops::Add;

use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, SerializeMap, Serializer},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
pub struct Tstr(String); // Time string

generate_tagged!((
    0,
    TaggedTstr,
    Tstr,
    "text string",
    "representation of date/time string using CBOR tag 0"
));

/// Represents timestamps used in coserv query and results
#[derive(Debug, From, Default, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TimeStamp(pub DateTime<FixedOffset>);

/// Re-export to perform arithmetic on TimeStamp.
pub use chrono::TimeDelta;

impl TimeStamp {
    pub fn now() -> Self {
        Local::now().fixed_offset().into()
    }

    pub fn add(&self, delta: TimeDelta) -> Self {
        self.0.add(delta).into()
    }
}

impl Serialize for TimeStamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        //  Section 3.3 of [RFC4287]
        let tagged_time = TaggedTstr::from(Tstr(self.0.to_rfc3339_opts(SecondsFormat::Secs, true)));
        tagged_time.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TimeStamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let time_tstr = TaggedTstr::deserialize(deserializer)?.0 .0 .0;
        Ok(TimeStamp(
            DateTime::parse_from_rfc3339(&time_tstr).map_err(D::Error::custom)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_string() {
        let tests: Vec<(TimeStamp, Vec<u8>)> = vec![
            (
                TimeStamp(DateTime::parse_from_rfc3339("2020-09-04T18:34:39+05:30").unwrap()),
                vec![
                    0xc0, 0x78, 0x19, // tag(0), text(25)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x38,
                    0x3a, 0x33, 0x34, 0x3a, 0x33, 0x39, 0x2b, 0x30, 0x35, 0x3a, 0x33, 0x30,
                ],
            ),
            (
                TimeStamp(DateTime::parse_from_rfc3339("2020-09-04T13:04:39+00:00").unwrap()),
                vec![
                    0xc0, 0x74, // tag(0), text(20)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33,
                    0x3a, 0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a,
                ],
            ),
            (
                TimeStamp(DateTime::parse_from_rfc3339("2020-09-04T13:04:39Z").unwrap()),
                vec![
                    0xc0, 0x74, // tag(0), text(20)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33,
                    0x3a, 0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a,
                ],
            ),
        ];

        for (i, (time, expected_cbor)) in tests.iter().enumerate() {
            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&time, &mut actual_cbor).unwrap();
            assert_eq!(*expected_cbor, actual_cbor, "ser at index {i}: {time:?}");

            let time_de: TimeStamp = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(*time, time_de, "de at index {i}: {time:?} != {time_de:?}");
        }

        let err: Result<TimeStamp, _> =
            ciborium::from_reader([0xc0_u8, 0x63, 0x66, 0x6f, 0x6f].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_time_add() {
        let base_time = DateTime::parse_from_rfc3339("2020-09-04T00:00:00Z").unwrap();
        let expected_time = DateTime::parse_from_rfc3339("2020-09-04T01:00:00Z").unwrap();
        let result = base_time.add(TimeDelta::hours(1));
        assert_eq!(result, expected_time);
    }
}
