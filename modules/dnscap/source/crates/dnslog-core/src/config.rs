use aes_gcm::aead::{rand_core::RngCore, OsRng};
use anyhow::{Context, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub storage: StorageConfig,
    pub capture: CaptureConfig,
    pub agent: AgentConfig,
    pub client: ClientConfig,
    pub collector: CollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StorageConfig {
    pub root: PathBuf,
    pub flush_interval_ms: u64,
    pub retention_days: u64,
    pub format: StorageFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageFormat {
    Json,
    Csv,
}

impl StorageFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "jsonl",
            Self::Csv => "csv",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CaptureConfig {
    pub interface: String,
    pub capture_udp_53: bool,
    pub capture_tcp_53: bool,
    pub log_queries: bool,
    pub log_responses: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentConfig {
    pub mode: AgentMode,
    pub max_queue_events: usize,
    pub drop_when_full: bool,
    pub health_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    Single,
    Client,
    #[serde(alias = "collector")]
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ClientConfig {
    pub collector_addr: String,
    pub shared_token: String,
    pub source_id: String,
    pub forward_queue_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CollectorConfig {
    pub listen_addr: String,
    pub shared_token: String,
    pub allowed_subnets: Vec<String>,
    pub max_remote_queue_events: usize,
    pub max_clients: usize,
    pub max_frame_bytes: usize,
    pub read_timeout_seconds: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("./logs"),
            flush_interval_ms: 1_000,
            retention_days: 90,
            format: StorageFormat::Json,
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "auto".to_string(),
            capture_udp_53: true,
            capture_tcp_53: true,
            log_queries: true,
            log_responses: false,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            mode: AgentMode::Single,
            max_queue_events: 10_000,
            drop_when_full: true,
            health_interval_seconds: 60,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            collector_addr: "127.0.0.1:53530".to_string(),
            shared_token: "change-me".to_string(),
            source_id: "auto".to_string(),
            forward_queue_events: 10_000,
        }
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:53530".to_string(),
            shared_token: "change-me".to_string(),
            allowed_subnets: Vec::new(),
            max_remote_queue_events: 10_000,
            max_clients: 128,
            max_frame_bytes: 1_048_576,
            read_timeout_seconds: 30,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => Self::load(path),
            None => Self::load(default_config_path()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.agent.max_queue_events > 0,
            "agent.max_queue_events must be greater than zero"
        );
        anyhow::ensure!(
            self.storage.flush_interval_ms > 0,
            "storage.flush_interval_ms must be greater than zero"
        );
        anyhow::ensure!(
            self.storage.retention_days > 0,
            "storage.retention_days must be greater than zero"
        );
        anyhow::ensure!(
            self.agent.health_interval_seconds > 0,
            "agent.health_interval_seconds must be greater than zero"
        );
        anyhow::ensure!(
            self.client.forward_queue_events > 0,
            "client.forward_queue_events must be greater than zero"
        );
        anyhow::ensure!(
            self.collector.max_remote_queue_events > 0,
            "collector.max_remote_queue_events must be greater than zero"
        );
        anyhow::ensure!(
            self.collector.max_clients > 0,
            "collector.max_clients must be greater than zero"
        );
        anyhow::ensure!(
            self.collector.max_frame_bytes >= 1024,
            "collector.max_frame_bytes must be at least 1024"
        );
        anyhow::ensure!(
            self.collector.read_timeout_seconds > 0,
            "collector.read_timeout_seconds must be greater than zero"
        );
        if self.agent.mode == AgentMode::Client {
            anyhow::ensure!(
                !self.client.collector_addr.trim().is_empty(),
                "client.collector_addr must not be empty in client mode"
            );
            validate_shared_token(&self.client.shared_token, "client.shared_token")?;
        }
        if self.agent.mode == AgentMode::Host {
            anyhow::ensure!(
                !self.collector.listen_addr.trim().is_empty(),
                "collector.listen_addr must not be empty in collector mode"
            );
            validate_shared_token(&self.collector.shared_token, "collector.shared_token")?;
            anyhow::ensure!(
                !self.collector.allowed_subnets.is_empty(),
                "collector.allowed_subnets must be set in host mode; use configure-host to generate a host config"
            );
        }
        anyhow::ensure!(
            self.capture.capture_udp_53 || self.capture.capture_tcp_53,
            "at least one of capture.capture_udp_53 or capture.capture_tcp_53 must be true"
        );
        anyhow::ensure!(
            self.capture.log_queries || self.capture.log_responses,
            "at least one of capture.log_queries or capture.log_responses must be true"
        );
        Ok(())
    }
}

fn validate_shared_token(token: &str, field: &str) -> Result<()> {
    let trimmed = token.trim();
    let lower = trimmed.to_ascii_lowercase();
    let placeholders = [
        "change-me",
        "change-me-use-a-long-random-secret",
        "replace-with-a-long-random-secret",
        "generate-a-fresh-32-byte-random-token",
        "secret",
        "password",
        "test",
    ];

    anyhow::ensure!(!trimmed.is_empty(), "{field} must not be empty");
    anyhow::ensure!(
        trimmed.len() >= 32,
        "{field} must be at least 32 characters"
    );
    anyhow::ensure!(
        !placeholders.contains(&lower.as_str()),
        "{field} must not use a placeholder value"
    );
    anyhow::ensure!(
        trimmed
            .chars()
            .all(|ch| !ch.is_control() && !ch.is_whitespace()),
        "{field} must not contain whitespace or control characters"
    );
    Ok(())
}

pub fn generate_shared_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    BASE64_STANDARD_NO_PAD.encode(bytes)
}

pub fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\DnsLog\config.toml")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/dnslog/config.toml")
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        PathBuf::from("/etc/dnslog/config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_loading_applies_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[storage]\nroot = \"./x\"\n").unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.storage.root, PathBuf::from("./x"));
        assert_eq!(config.capture.interface, "auto");
        assert_eq!(config.agent.max_queue_events, 10_000);
        assert_eq!(config.agent.mode, AgentMode::Single);
    }

    #[test]
    fn config_rejects_zero_queue() {
        let config = Config {
            agent: AgentConfig {
                max_queue_events: 0,
                ..AgentConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn client_mode_accepts_hostname_collector_addr() {
        let config = Config {
            agent: AgentConfig {
                mode: AgentMode::Client,
                ..AgentConfig::default()
            },
            client: ClientConfig {
                collector_addr: "dnslog-host.local:53530".to_string(),
                shared_token: "LongRandomSecretTokenForTests12345".to_string(),
                ..ClientConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn client_mode_rejects_placeholder_token() {
        let config = Config {
            agent: AgentConfig {
                mode: AgentMode::Client,
                ..AgentConfig::default()
            },
            client: ClientConfig {
                shared_token: "change-me-use-a-long-random-secret".to_string(),
                ..ClientConfig::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn generated_shared_token_passes_validation() {
        validate_shared_token(&generate_shared_token(), "shared_token").unwrap();
    }
}
