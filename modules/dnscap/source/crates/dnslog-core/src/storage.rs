use crate::config::StorageFormat;
use crate::event::{DnsQueryEvent, HealthEvent, LogEvent};
use crate::rotate::{daily_log_path, local_date_for};
use anyhow::{Context, Result};
use chrono::{DateTime, Days, NaiveDate, Utc};
use crossbeam_channel::{Receiver, RecvTimeoutError};
use csv::Writer;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DNS_HEADER: &[&str] = &[
    "ts",
    "host",
    "os",
    "interface",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "qname",
    "qtype",
];

const HEALTH_HEADER: &[&str] = &[
    "ts",
    "event",
    "captured_packets",
    "parsed_dns_queries",
    "parse_errors",
    "dropped_events",
    "queue_depth",
];

pub struct WriterConfig {
    pub root: PathBuf,
    pub flush_interval: Duration,
    pub retention_days: u64,
    pub format: StorageFormat,
}

pub fn run_writer(receiver: Receiver<LogEvent>, config: WriterConfig) -> Result<()> {
    prune_retention(&config.root, config.retention_days)?;
    let mut files = EventFiles::new(config.root, config.retention_days, config.format);
    let mut last_flush = Instant::now();

    loop {
        match receiver.recv_timeout(config.flush_interval) {
            Ok(LogEvent::Dns(event)) => files.write_dns(&event)?,
            Ok(LogEvent::Health(event)) => files.write_health(&event)?,
            Ok(LogEvent::Shutdown) => {
                files.flush_all()?;
                return Ok(());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                files.flush_all()?;
                return Ok(());
            }
        }

        if last_flush.elapsed() >= config.flush_interval {
            files.flush_all()?;
            last_flush = Instant::now();
        }
    }
}

struct EventFiles {
    root: PathBuf,
    retention_days: u64,
    format: StorageFormat,
    dns: Option<DailyFile>,
    health: Option<DailyFile>,
}

impl EventFiles {
    fn new(root: PathBuf, retention_days: u64, format: StorageFormat) -> Self {
        Self {
            root,
            retention_days,
            format,
            dns: None,
            health: None,
        }
    }

    fn write_dns(&mut self, event: &DnsQueryEvent) -> Result<()> {
        let ts = event.ts;
        self.prune_if_new_day(ts)?;
        write_event_row(
            &self.root,
            &mut self.dns,
            "dns",
            DNS_HEADER,
            ts,
            event,
            self.format,
        )
    }

    fn write_health(&mut self, event: &HealthEvent) -> Result<()> {
        let ts = event.ts;
        self.prune_if_new_day(ts)?;
        write_event_row(
            &self.root,
            &mut self.health,
            "health",
            HEALTH_HEADER,
            ts,
            event,
            self.format,
        )
    }

    fn flush_all(&mut self) -> Result<()> {
        if let Some(file) = &mut self.dns {
            file.writer.flush().context("failed to flush dns log")?;
        }
        if let Some(file) = &mut self.health {
            file.writer.flush().context("failed to flush health log")?;
        }
        Ok(())
    }

    fn prune_if_new_day(&self, ts: DateTime<Utc>) -> Result<()> {
        let date = local_date_for(ts);
        let dns_date = self.dns.as_ref().map(|file| file.date);
        let health_date = self.health.as_ref().map(|file| file.date);
        if dns_date != Some(date) && health_date != Some(date) {
            prune_retention(&self.root, self.retention_days)?;
        }
        Ok(())
    }
}

struct DailyFile {
    date: chrono::NaiveDate,
    writer: EventWriter,
}

enum EventWriter {
    Csv(Box<Writer<BufWriter<File>>>),
    Json(BufWriter<File>),
}

impl EventWriter {
    fn flush(&mut self) -> Result<()> {
        match self {
            Self::Csv(writer) => writer.flush()?,
            Self::Json(writer) => writer.flush()?,
        }
        Ok(())
    }
}

fn write_event_row<T: serde::Serialize>(
    root: &Path,
    slot: &mut Option<DailyFile>,
    kind: &str,
    header: &[&str],
    ts: DateTime<Utc>,
    event: &T,
    format: StorageFormat,
) -> Result<()> {
    let date = local_date_for(ts);
    if slot.as_ref().map(|file| file.date) != Some(date) {
        let path = daily_log_path(root, date, kind, format.extension());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open log file {}", path.display()))?;
        let is_new_file = file
            .metadata()
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(false);
        let writer = match format {
            StorageFormat::Csv => {
                let mut writer = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_writer(BufWriter::new(file));
                if is_new_file {
                    writer
                        .write_record(header)
                        .with_context(|| format!("failed to write {kind} csv header"))?;
                }
                EventWriter::Csv(Box::new(writer))
            }
            StorageFormat::Json => EventWriter::Json(BufWriter::new(file)),
        };
        *slot = Some(DailyFile { date, writer });
    }

    let writer = &mut slot.as_mut().expect("daily file should be opened").writer;
    match writer {
        EventWriter::Csv(writer) => writer
            .serialize(event)
            .with_context(|| format!("failed to write {kind} csv row"))?,
        EventWriter::Json(writer) => {
            serde_json::to_writer(&mut *writer, event)
                .with_context(|| format!("failed to write {kind} json row"))?;
            writer
                .write_all(b"\n")
                .with_context(|| format!("failed to write {kind} json newline"))?;
        }
    }
    Ok(())
}

pub fn prune_retention(root: &Path, retention_days: u64) -> Result<()> {
    if retention_days == 0 || !root.exists() {
        return Ok(());
    }

    let today = local_date_for(Utc::now());
    let cutoff = today
        .checked_sub_days(Days::new(retention_days.saturating_sub(1)))
        .unwrap_or(NaiveDate::MIN);

    for year_entry in std::fs::read_dir(root)
        .with_context(|| format!("failed to read log root {}", root.display()))?
    {
        let year_entry = year_entry?;
        if !year_entry.file_type()?.is_dir() {
            continue;
        }
        let Some(year) = parse_u32_component(&year_entry.file_name()) else {
            continue;
        };

        for month_entry in std::fs::read_dir(year_entry.path())? {
            let month_entry = month_entry?;
            if !month_entry.file_type()?.is_dir() {
                continue;
            }
            let Some(month) = parse_u32_component(&month_entry.file_name()) else {
                continue;
            };

            for day_entry in std::fs::read_dir(month_entry.path())? {
                let day_entry = day_entry?;
                if !day_entry.file_type()?.is_dir() {
                    continue;
                }
                let Some(day) = parse_u32_component(&day_entry.file_name()) else {
                    continue;
                };
                let Some(date) = NaiveDate::from_ymd_opt(year as i32, month, day) else {
                    continue;
                };
                if date < cutoff {
                    std::fs::remove_dir_all(day_entry.path()).with_context(|| {
                        format!(
                            "failed to prune old log directory {}",
                            day_entry.path().display()
                        )
                    })?;
                }
            }
            remove_dir_if_empty(&month_entry.path())?;
        }
        remove_dir_if_empty(&year_entry.path())?;
    }

    Ok(())
}

fn parse_u32_component(value: &std::ffi::OsStr) -> Option<u32> {
    value.to_str()?.parse().ok()
}

fn remove_dir_if_empty(path: &Path) -> Result<()> {
    if std::fs::read_dir(path)?.next().is_none() {
        std::fs::remove_dir(path)
            .with_context(|| format!("failed to remove empty log directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StorageFormat;
    use chrono::{TimeZone, Timelike};
    use std::fs;

    #[test]
    fn retention_prunes_old_daily_directories() {
        let dir = tempfile::tempdir().unwrap();
        let today = local_date_for(Utc::now());
        let old = today.checked_sub_days(Days::new(95)).unwrap();
        let recent = today.checked_sub_days(Days::new(5)).unwrap();

        let old_dir = crate::rotate::daily_dir(dir.path(), old);
        let recent_dir = crate::rotate::daily_dir(dir.path(), recent);
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&recent_dir).unwrap();
        fs::write(old_dir.join("dns.csv"), "old").unwrap();
        fs::write(recent_dir.join("dns.csv"), "recent").unwrap();

        prune_retention(dir.path(), 90).unwrap();

        assert!(!old_dir.exists());
        assert!(recent_dir.exists());
    }

    #[test]
    fn writes_dns_event_as_json_line_by_default_format() {
        let dir = tempfile::tempdir().unwrap();
        let event = test_dns_event();
        let ts = event.ts;
        let mut slot = None;

        write_event_row(
            dir.path(),
            &mut slot,
            "dns",
            DNS_HEADER,
            ts,
            &event,
            StorageFormat::Json,
        )
        .unwrap();
        slot.as_mut().unwrap().writer.flush().unwrap();

        let path = daily_log_path(dir.path(), local_date_for(ts), "dns", "jsonl");
        let raw = fs::read_to_string(path).unwrap();
        assert_eq!(
            raw,
            "{\"ts\":\"2026-05-02T10:31:22.123Z\",\"host\":\"laptop-01\",\"os\":\"macos\",\"interface\":\"en0\",\"src_ip\":\"192.168.1.44\",\"dst_ip\":\"1.1.1.1\",\"src_port\":55321,\"dst_port\":53,\"proto\":\"udp\",\"qname\":\"example.com\",\"qtype\":\"A\"}\n"
        );
    }

    #[test]
    fn writes_dns_event_as_csv_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let event = test_dns_event();
        let ts = event.ts;
        let mut slot = None;

        write_event_row(
            dir.path(),
            &mut slot,
            "dns",
            DNS_HEADER,
            ts,
            &event,
            StorageFormat::Csv,
        )
        .unwrap();
        slot.as_mut().unwrap().writer.flush().unwrap();

        let path = daily_log_path(dir.path(), local_date_for(ts), "dns", "csv");
        let raw = fs::read_to_string(path).unwrap();
        assert_eq!(
            raw,
            "ts,host,os,interface,src_ip,dst_ip,src_port,dst_port,proto,qname,qtype\n2026-05-02T10:31:22.123Z,laptop-01,macos,en0,192.168.1.44,1.1.1.1,55321,53,udp,example.com,A\n"
        );
    }

    fn test_dns_event() -> DnsQueryEvent {
        DnsQueryEvent {
            ts: Utc
                .with_ymd_and_hms(2026, 5, 2, 10, 31, 22)
                .unwrap()
                .with_nanosecond(123_000_000)
                .unwrap(),
            host: "laptop-01".to_string(),
            os: "macos".to_string(),
            interface: "en0".to_string(),
            src_ip: "192.168.1.44".to_string(),
            dst_ip: "1.1.1.1".to_string(),
            src_port: 55321,
            dst_port: 53,
            proto: "udp".to_string(),
            qname: "example.com".to_string(),
            qtype: "A".to_string(),
        }
    }
}
