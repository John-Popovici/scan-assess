use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsQueryEvent {
    #[serde(with = "rfc3339_millis")]
    pub ts: DateTime<Utc>,
    pub host: String,
    pub os: String,
    pub interface: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub qname: String,
    pub qtype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthEvent {
    #[serde(with = "rfc3339_millis")]
    pub ts: DateTime<Utc>,
    pub event: String,
    pub captured_packets: u64,
    pub parsed_dns_queries: u64,
    pub parse_errors: u64,
    pub dropped_events: u64,
    pub queue_depth: usize,
}

impl HealthEvent {
    pub fn new(
        captured_packets: u64,
        parsed_dns_queries: u64,
        parse_errors: u64,
        dropped_events: u64,
        queue_depth: usize,
    ) -> Self {
        Self {
            ts: Utc::now(),
            event: "health".to_string(),
            captured_packets,
            parsed_dns_queries,
            parse_errors,
            dropped_events,
            queue_depth,
        }
    }
}

#[derive(Debug, Clone)]
pub enum LogEvent {
    Dns(DnsQueryEvent),
    Health(HealthEvent),
    Shutdown,
}

impl LogEvent {
    pub fn kind(&self) -> Option<&'static str> {
        match self {
            Self::Dns(_) => Some("dns"),
            Self::Health(_) => Some("health"),
            Self::Shutdown => None,
        }
    }
}

pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
}

pub fn hostname_string() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

mod rfc3339_millis {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(ts: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<DateTime<Utc>>()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

    #[test]
    fn dns_event_serializes_as_csv_record() {
        let event = DnsQueryEvent {
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
        };

        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(Vec::new());
        writer.serialize(&event).unwrap();
        let csv = String::from_utf8(writer.into_inner().unwrap()).unwrap();
        assert_eq!(
            csv,
            "2026-05-02T10:31:22.123Z,laptop-01,macos,en0,192.168.1.44,1.1.1.1,55321,53,udp,example.com,A\n"
        );
    }
}
