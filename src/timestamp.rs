//! RFC 3339 timestamps, as far as a licence needs them: read one, compare two,
//! and count the days between them.
//!
//! The licence code used `chrono` for exactly this. `chrono` is no longer
//! maintained (RUSTSEC-2026-0543), and a date library is a large thing to
//! carry for three calls, so the three calls are here.
//!
//! [`Timestamp::parse_rfc3339`] accepts the strings
//! `chrono::DateTime::parse_from_rfc3339` accepted, refuses the ones it
//! refused, and puts each at the same instant. That is a requirement, not a
//! convenience: a commercial licence whose `expires_at` cannot be read is
//! reported as expired, so a reader that was stricter would switch off
//! licences that are valid today. The two were compared on generated input
//! before `chrono` was removed; the cases below are the ones that comparison
//! showed to matter.

use std::fmt;

const SECONDS_PER_DAY: i64 = 86_400;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
/// The largest offset RFC 3339 can state, `23:59`, in seconds.
const MAX_OFFSET_SECONDS: i64 = (23 * 60 + 59) * 60;

/// An instant in UTC.
///
/// Ordered by time: the derived ordering compares `secs` and then `nanos`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timestamp {
    /// Whole seconds since 1970-01-01T00:00:00Z, negative before it.
    secs: i64,
    /// Nanoseconds past `secs`. Below one second, except inside a leap second
    /// (`23:59:60`): that is kept as the second before it with a full second
    /// added here, so it sorts after `23:59:59.999999999` and before the
    /// second that follows, and its Unix time is that of `23:59:59`.
    nanos: u32,
}

impl Timestamp {
    /// Read an RFC 3339 timestamp, such as `2027-01-31T23:59:59Z` or
    /// `2027-01-31t23:59:59.25+02:00`. `None` if it is not one.
    pub(crate) fn parse_rfc3339(input: &str) -> Option<Self> {
        let s = input.as_bytes();
        let mut at = 0;

        let year = number(s, &mut at, 4)?;
        literal(s, &mut at, b'-')?;
        let month = number(s, &mut at, 2)?;
        literal(s, &mut at, b'-')?;
        let day = number(s, &mut at, 2)?;
        match s.get(at)? {
            b'T' | b't' | b' ' => at += 1,
            _ => return None,
        }
        let hour = number(s, &mut at, 2)?;
        literal(s, &mut at, b':')?;
        let minute = number(s, &mut at, 2)?;
        literal(s, &mut at, b':')?;
        let second = number(s, &mut at, 2)?;

        // Any number of fraction digits; those past the ninth are dropped.
        let mut nanos = 0;
        if s.get(at) == Some(&b'.') {
            at += 1;
            let first = at;
            let mut unit = NANOS_PER_SECOND / 10;
            while let Some(digit @ b'0'..=b'9') = s.get(at).copied() {
                nanos += u32::from(digit - b'0') * unit;
                unit /= 10;
                at += 1;
            }
            if at == first {
                return None;
            }
        }

        let offset = match s.get(at)? {
            b'Z' | b'z' => {
                at += 1;
                0
            }
            _ => {
                let rest = &input[at..];
                // U+2212 MINUS SIGN is accepted beside the ASCII hyphen.
                let (negative, sign_len) = match rest.chars().next()? {
                    '+' => (false, 1),
                    '-' => (true, 1),
                    '\u{2212}' => (true, '\u{2212}'.len_utf8()),
                    _ => return None,
                };
                at += sign_len;
                let hours = number(s, &mut at, 2)?;
                literal(s, &mut at, b':')?;
                let minutes = number(s, &mut at, 2)?;
                let seconds = hours * 3_600 + minutes * 60;
                if minutes > 59 || seconds > MAX_OFFSET_SECONDS {
                    return None;
                }
                if negative {
                    -seconds
                } else {
                    seconds
                }
            }
        };
        if at != s.len() {
            return None;
        }

        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 60
        {
            return None;
        }
        let (second, nanos) = if second == 60 {
            (59, nanos + NANOS_PER_SECOND)
        } else {
            (second, nanos)
        };

        let local = days_from_civil(year, month, day) * SECONDS_PER_DAY
            + hour * 3_600
            + minute * 60
            + second;
        Some(Self {
            secs: local - offset,
            nanos,
        })
    }

    /// Seconds since the Unix epoch, rounded down.
    pub(crate) fn unix_seconds(self) -> i64 {
        self.secs
    }

    /// The current time.
    #[cfg(feature = "licensing")]
    pub(crate) fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => Self {
                secs: i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
                nanos: since.subsec_nanos(),
            },
            // A clock set before 1970. Keep `nanos` counting forwards.
            Err(before) => {
                let before = before.duration();
                let whole = i64::try_from(before.as_secs()).unwrap_or(i64::MAX);
                match before.subsec_nanos() {
                    0 => Self {
                        secs: -whole,
                        nanos: 0,
                    },
                    part => Self {
                        secs: -whole - 1,
                        nanos: NANOS_PER_SECOND - part,
                    },
                }
            }
        }
    }

    /// Whole days from `self` until `later`, rounded towards zero; negative
    /// when `later` is earlier.
    #[cfg(feature = "licensing")]
    pub(crate) fn whole_days_until(self, later: Self) -> i64 {
        let nanos = (i128::from(later.secs) - i128::from(self.secs)) * i128::from(NANOS_PER_SECOND)
            + (i128::from(later.nanos) - i128::from(self.nanos));
        let days = nanos / (i128::from(SECONDS_PER_DAY) * i128::from(NANOS_PER_SECOND));
        i64::try_from(days).unwrap_or(if days < 0 { i64::MIN } else { i64::MAX })
    }

    /// `self` moved by whole seconds and nanoseconds, for tests.
    #[cfg(all(test, feature = "licensing"))]
    pub(crate) fn offset_by(self, secs: i64, nanos: i64) -> Self {
        let total = i128::from(self.secs) * i128::from(NANOS_PER_SECOND)
            + i128::from(self.nanos)
            + i128::from(secs) * i128::from(NANOS_PER_SECOND)
            + i128::from(nanos);
        let per = i128::from(NANOS_PER_SECOND);
        Self {
            secs: i64::try_from(total.div_euclid(per)).unwrap(),
            nanos: u32::try_from(total.rem_euclid(per)).unwrap(),
        }
    }
}

/// Written as RFC 3339 in UTC, which is what belongs in a log line.
impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = civil_from_days(self.secs.div_euclid(SECONDS_PER_DAY));
        let of_day = self.secs.rem_euclid(SECONDS_PER_DAY);
        let (hour, minute) = (of_day / 3_600, of_day % 3_600 / 60);
        let (second, nanos) = if self.nanos >= NANOS_PER_SECOND {
            (of_day % 60 + 1, self.nanos - NANOS_PER_SECOND)
        } else {
            (of_day % 60, self.nanos)
        };
        // A year the format itself cannot write is reached only through an
        // offset at either end of the range; it is given a sign, as ISO 8601
        // does for expanded years.
        if (0..=9_999).contains(&year) {
            write!(f, "{year:04}")?;
        } else {
            write!(f, "{year:+05}")?;
        }
        write!(f, "-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")?;
        if nanos != 0 {
            write!(f, ".{nanos:09}")?;
        }
        f.write_str("Z")
    }
}

/// Exactly `width` ASCII digits at `at`, as a number.
fn number(s: &[u8], at: &mut usize, width: usize) -> Option<i64> {
    let digits = s.get(*at..*at + width)?;
    let mut value = 0;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(digit - b'0');
    }
    *at += width;
    Some(value)
}

fn literal(s: &[u8], at: &mut usize, expected: u8) -> Option<()> {
    if *s.get(*at)? == expected {
        *at += 1;
        Some(())
    } else {
        None
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap_year(year) => 29,
        _ => 28,
    }
}

/// Days from 1970-01-01 to a date in the proleptic Gregorian calendar.
///
/// The year is counted from March, so that the leap day is the last day of
/// its year and each 400-year cycle has the same length (146,097 days).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`]: year, month and day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(input: &str) -> Option<i64> {
        Timestamp::parse_rfc3339(input).map(Timestamp::unix_seconds)
    }

    #[test]
    fn known_instants() {
        assert_eq!(unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix("2026-08-16T00:00:00Z"), Some(1_786_838_400));
        assert_eq!(unix("2099-12-31T23:59:59Z"), Some(4_102_444_799));
        assert_eq!(unix("2000-02-29T12:00:00Z"), Some(951_825_600));
        assert_eq!(unix("1969-12-31T23:59:59Z"), Some(-1));
        // The first and last years the format can write.
        assert_eq!(unix("0000-01-01T00:00:00Z"), Some(-62_167_219_200));
        assert_eq!(unix("9999-12-31T23:59:59Z"), Some(253_402_300_799));
    }

    #[test]
    fn an_offset_moves_the_instant() {
        assert_eq!(
            unix("2026-01-01T02:00:00+02:00"),
            unix("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            unix("2025-12-31T19:00:00-05:00"),
            unix("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            unix("2025-12-31T19:00:00\u{2212}05:00"),
            unix("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            unix("2026-01-01T00:00:00+00:00"),
            unix("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            unix("2026-01-01T23:59:00+23:59"),
            unix("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn the_separator_and_the_zone_letter_may_be_lower_case() {
        let expected = unix("2026-01-01T00:00:00Z");
        for form in [
            "2026-01-01t00:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00z",
        ] {
            assert_eq!(unix(form), expected, "{form}");
        }
    }

    #[test]
    fn fractions_order_instants_within_a_second() {
        let whole = Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap();
        let tenth = Timestamp::parse_rfc3339("2026-01-01T00:00:00.1Z").unwrap();
        let nano = Timestamp::parse_rfc3339("2026-01-01T00:00:00.000000001Z").unwrap();
        let next = Timestamp::parse_rfc3339("2026-01-01T00:00:01Z").unwrap();
        assert!(whole < nano && nano < tenth && tenth < next);
        // Digits past the ninth are dropped, not rounded.
        assert_eq!(
            Timestamp::parse_rfc3339("2026-01-01T00:00:00.0000000019Z").unwrap(),
            nano
        );
        assert_eq!(tenth.unix_seconds(), whole.unix_seconds());
    }

    #[test]
    fn a_leap_second_lies_between_the_seconds_around_it() {
        let before = Timestamp::parse_rfc3339("2016-12-31T23:59:59.999999999Z").unwrap();
        let leap = Timestamp::parse_rfc3339("2016-12-31T23:59:60Z").unwrap();
        let after = Timestamp::parse_rfc3339("2017-01-01T00:00:00Z").unwrap();
        assert!(before < leap && leap < after);
        assert_eq!(leap.unix_seconds(), before.unix_seconds());
        assert_eq!(format!("{leap:?}"), "2016-12-31T23:59:60Z");
    }

    #[test]
    fn what_is_not_a_timestamp_is_refused() {
        for input in [
            "",
            "not-a-date",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00Z",
            "2026-1-01T00:00:00Z",
            "02026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z ",
            " 2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00,5Z",
            "2026-01-01T00:00:00+0200",
            "2026-01-01T00:00:00+02",
            "2026-01-01T00:00:00+24:00",
            "2026-01-01T00:00:00+02:60",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:61Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2099-02-30T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-01-01X00:00:00Z",
            "２０２６-01-01T00:00:00Z",
        ] {
            assert_eq!(unix(input), None, "{input:?}");
        }
    }

    #[test]
    fn a_leap_day_exists_only_in_a_leap_year() {
        assert!(unix("2024-02-29T00:00:00Z").is_some());
        assert!(unix("2000-02-29T00:00:00Z").is_some());
        assert!(unix("0000-02-29T00:00:00Z").is_some());
        assert!(unix("2100-02-29T00:00:00Z").is_none());
    }

    #[test]
    fn dates_and_day_numbers_convert_both_ways() {
        // Every day across the leap rules of three centuries, and the ends of
        // the range the format can write.
        let first = days_from_civil(1899, 1, 1);
        let last = days_from_civil(2201, 1, 1);
        for days in (first..=last).chain([
            days_from_civil(0, 1, 1),
            days_from_civil(0, 12, 31),
            days_from_civil(9999, 12, 31),
        ]) {
            let (year, month, day) = civil_from_days(days);
            assert!((1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day));
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn it_is_written_as_it_is_read() {
        for input in [
            "1970-01-01T00:00:00Z",
            "2027-01-31T23:59:59Z",
            "0000-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
            "2026-06-15T08:30:00.250000000Z",
        ] {
            let parsed = Timestamp::parse_rfc3339(input).unwrap();
            assert_eq!(format!("{parsed:?}"), input);
        }
    }

    #[cfg(feature = "licensing")]
    #[test]
    fn days_between_round_towards_zero() {
        let start = Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap();
        let almost = Timestamp::parse_rfc3339("2026-01-02T23:59:59.999999999Z").unwrap();
        let two = Timestamp::parse_rfc3339("2026-01-03T00:00:00Z").unwrap();
        assert_eq!(start.whole_days_until(almost), 1);
        assert_eq!(start.whole_days_until(two), 2);
        assert_eq!(almost.whole_days_until(start), -1);
        assert_eq!(two.whole_days_until(start), -2);
        assert_eq!(start.whole_days_until(start), 0);
    }

    #[cfg(feature = "licensing")]
    #[test]
    fn the_clock_reads_a_plausible_time() {
        let now = Timestamp::now();
        assert!(now > Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap());
        assert!(now.nanos < NANOS_PER_SECOND);
    }
}
