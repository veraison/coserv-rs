// SPDX-License-Identifier: Apache-2.0

use corim_rs::generate_tagged;
use derive_more::{Display, From};
use time::{OffsetDateTime, SignedDuration};

use serde::ser::SerializeMap; // required by generate_tagged!

generate_tagged!((
    0,
    TaggedTimeStamp,
    TimeStamp,
    "text string",
    "representation of date/time string using CBOR tag 0"
));

/// Represents timestamps used in coserv results.
/// Timestamps are in UTC when they are created. But any rfc3339 string
/// can be parsed into a timestamp. Internally uses [time::OffsetDateTime].
#[derive(
    Debug,
    Display,
    From,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TimeStamp(#[serde(with = "time::serde::rfc3339")] pub OffsetDateTime);

impl TimeStamp {
    // Returns the current UTC timestamp
    pub fn now() -> Self {
        OffsetDateTime::now_utc().into()
    }

    // Adds seconds to the timestamp
    pub fn add(&self, delta: u32) -> Self {
        let delta = SignedDuration::seconds(delta.into());
        self.0
            .checked_add(delta)
            .expect("duration too small to go beyond the range")
            .into()
    }

    // Returns the unix timestamp
    pub fn unix(&self) -> u64 {
        self.0
            .unix_timestamp()
            .try_into()
            .expect("did not expect negative timestamp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_time_string() {
        let tests: Vec<(TaggedTimeStamp, Vec<u8>)> = vec![
            (
                TaggedTimeStamp::from(TimeStamp(datetime!(2020-09-04 18:34:39 +5:30))),
                vec![
                    0xc0, 0x78, 0x19, // tag(0), text(25)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x38,
                    0x3a, 0x33, 0x34, 0x3a, 0x33, 0x39, 0x2b, 0x30, 0x35, 0x3a, 0x33, 0x30,
                ],
            ),
            (
                TaggedTimeStamp::from(TimeStamp(datetime!(2020-09-04 13:04:39 +0:00))),
                vec![
                    0xc0, 0x74, // tag(0), text(20)
                    0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x39, 0x2d, 0x30, 0x34, 0x54, 0x31, 0x33,
                    0x3a, 0x30, 0x34, 0x3a, 0x33, 0x39, 0x5a,
                ],
            ),
            (
                TaggedTimeStamp::from(TimeStamp(datetime!(2020-09-04 13:04:39 UTC))),
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

            let time_de: TaggedTimeStamp = ciborium::from_reader(actual_cbor.as_slice()).unwrap();
            assert_eq!(*time, time_de, "de at index {i}: {time:?} != {time_de:?}");
        }

        let err: Result<TimeStamp, _> =
            ciborium::from_reader([0xc0_u8, 0x63, 0x66, 0x6f, 0x6f].as_slice());
        assert!(err.is_err());
    }

    #[test]
    fn test_time_add() {
        let base_time = TimeStamp(datetime!(2020-09-04 00:00:00 UTC));
        let expected_time = TimeStamp(datetime!(2020-09-04 01:00:00 UTC));
        let result = base_time.add(3600);
        assert_eq!(result, expected_time);
    }
}
