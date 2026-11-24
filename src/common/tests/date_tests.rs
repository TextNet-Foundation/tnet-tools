use super::*;
use std::time::Duration;

fn at(secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(secs)
}

#[test]
fn epoch_and_end_of_first_day() {
	assert_eq!(format_ymd(at(0)), "1970-01-01");
	assert_eq!(format_ymd(at(86_399)), "1970-01-01");
	assert_eq!(format_ymd(at(86_400)), "1970-01-02");
}

#[test]
fn known_dates() {
	assert_eq!(format_ymd(at(1_000_000_000)), "2001-09-09");
	assert_eq!(format_ymd(at(951_782_400)), "2000-02-29");
	assert_eq!(format_ymd(at(1_709_164_800)), "2024-02-29");
	assert_eq!(format_ymd(at(1_709_251_200)), "2024-03-01");
}

#[test]
fn before_epoch() {
	assert_eq!(
		format_ymd(UNIX_EPOCH - Duration::from_secs(1)),
		"1969-12-31"
	);
}

#[test]
fn extreme_values_do_not_panic() {
	let _ = format_ymd(UNIX_EPOCH + Duration::from_secs(u64::MAX / 2));
	let _ = format_ymd(UNIX_EPOCH - Duration::from_secs(u64::MAX / 2));
}
