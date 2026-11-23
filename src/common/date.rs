use std::time::{SystemTime, UNIX_EPOCH};

const SECS_PER_DAY: i64 = 86_400;

/// Formats a timestamp as a UTC `YYYY-MM-DD` date (the `Last-Modified` header format).
pub fn format_ymd(time: SystemTime) -> String {
	let secs = match time.duration_since(UNIX_EPOCH) {
		Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
		Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |s| -s),
	};

	let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));

	format!("{year:04}-{month:02}-{day:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let day_of_era = z.rem_euclid(146_097);
	let year_of_era =
		(day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
	let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
	let shifted_month = (5 * day_of_year + 2) / 153;
	let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
	let month = if shifted_month < 10 {
		shifted_month + 3
	} else {
		shifted_month - 9
	};
	let year = year_of_era + era * 400 + i64::from(month <= 2);

	(year, month, day)
}

#[cfg(test)]
#[path = "date_tests.rs"]
mod tests;
