use chrono::{DateTime, Datelike, Local, NaiveDate, Utc};
use std::path::{Path, PathBuf};

pub fn local_date_for(ts: DateTime<Utc>) -> NaiveDate {
    ts.with_timezone(&Local).date_naive()
}

pub fn daily_dir(root: &Path, date: NaiveDate) -> PathBuf {
    root.join(format!("{:04}", date.year()))
        .join(format!("{:02}", date.month()))
        .join(format!("{:02}", date.day()))
}

pub fn daily_log_path(root: &Path, date: NaiveDate, kind: &str, extension: &str) -> PathBuf {
    daily_dir(root, date).join(format!("{kind}.{extension}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_daily_path() {
        let date = NaiveDate::from_ymd_opt(2026, 5, 2).unwrap();
        let path = daily_log_path(Path::new("logs"), date, "dns", "jsonl");
        assert_eq!(path, PathBuf::from("logs/2026/05/02/dns.jsonl"));
    }
}
