use crate::collector::start_collector;
use crate::forwarder::{run_forwarder, ForwarderConfig};
use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender};
use dnslog_capture::{list_interfaces, run_capture_loop};
use dnslog_core::config::{generate_shared_token, AgentMode, Config, StorageFormat};
use dnslog_core::event::LogEvent;
use dnslog_core::storage::{run_writer, WriterConfig};
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;
use tracing::info;

pub fn run(
    config_path: Option<&Path>,
    duration: Option<Duration>,
    format_override: Option<StorageFormat>,
) -> Result<()> {
    let mut config = Config::load_or_default(config_path)?;
    if let Some(format) = format_override {
        config.storage.format = format;
    }
    let flush_interval = Duration::from_millis(config.storage.flush_interval_ms);
    let collector = if config.agent.mode == AgentMode::Host {
        Some(start_collector(
            config.collector.clone(),
            config.storage.root.clone(),
            flush_interval,
            config.storage.retention_days,
            config.storage.format,
        )?)
    } else {
        None
    };

    let (capture_sender, capture_receiver) = bounded(config.agent.max_queue_events);
    let (local_sender, local_receiver) = bounded(config.agent.max_queue_events);

    let writer_config = WriterConfig {
        root: config.storage.root.join("localhost"),
        flush_interval,
        retention_days: config.storage.retention_days,
        format: config.storage.format,
    };

    let writer = thread::spawn(move || run_writer(local_receiver, writer_config));
    let forward_sender = if config.agent.mode == AgentMode::Client {
        let (sender, receiver) = bounded(config.client.forward_queue_events);
        let forwarder_config = ForwarderConfig {
            collector_addr: config.client.collector_addr.clone(),
            token: config.client.shared_token.clone(),
            source_id: config.client.source_id.clone(),
        };
        thread::spawn(move || {
            if let Err(err) = run_forwarder(receiver, forwarder_config) {
                tracing::warn!(%err, "forwarder stopped");
            }
        });
        Some(sender)
    } else {
        None
    };

    let dispatcher =
        thread::spawn(move || dispatch_events(capture_receiver, local_sender, forward_sender));
    let counters = run_capture_loop(&config, capture_sender.clone(), duration)?;
    let _ = capture_sender.send(LogEvent::Shutdown);
    dispatcher
        .join()
        .map_err(|_| anyhow::anyhow!("dispatcher thread panicked"))?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("writer thread panicked"))?
        .context("writer failed")?;
    if let Some(collector) = collector {
        collector.stop().context("collector failed")?;
    }

    info!(
        captured_packets = counters.captured_packets,
        parsed_dns_queries = counters.parsed_dns_queries,
        parse_errors = counters.parse_errors,
        dropped_events = counters.dropped_events,
        "capture stopped"
    );
    Ok(())
}

fn dispatch_events(
    receiver: crossbeam_channel::Receiver<LogEvent>,
    local_sender: Sender<LogEvent>,
    forward_sender: Option<Sender<LogEvent>>,
) {
    while let Ok(event) = receiver.recv() {
        let is_shutdown = matches!(event, LogEvent::Shutdown);
        if is_shutdown {
            let _ = local_sender.send(LogEvent::Shutdown);
            if let Some(forward_sender) = &forward_sender {
                let _ = forward_sender.send(LogEvent::Shutdown);
            }
            break;
        }

        if local_sender.send(event.clone()).is_err() {
            break;
        }
        if let Some(forward_sender) = &forward_sender {
            let _ = forward_sender.try_send(event);
        }
    }
}

pub fn interfaces() -> Result<()> {
    for iface in list_interfaces()? {
        let description = iface.description.unwrap_or_default();
        let addresses = if iface.addresses.is_empty() {
            "-".to_string()
        } else {
            iface.addresses.join(", ")
        };
        println!("{}\t{}\t{}", iface.name, description, addresses);
    }
    Ok(())
}

pub fn validate_config(config_path: Option<&Path>) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    config.validate()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

pub fn configure_host(output: &Path) -> Result<()> {
    let mut config = Config::default();
    config.agent.mode = AgentMode::Host;

    println!("dnslog-agent host configuration");
    println!("Press Enter to accept the value shown in brackets.");

    config.storage.root = prompt_path("Log root", "./logs")?;
    config.capture.interface = prompt("Capture interface", "auto")?;
    config.collector.listen_addr = prompt("Collector listen address", "0.0.0.0:53530")?;
    config.collector.allowed_subnets = prompt_subnets("Allowed client subnets", "192.168.1.0/24")?;
    let generated_token = generate_shared_token();
    config.collector.shared_token = prompt("Shared token", &generated_token)?;

    config.validate()?;
    let rendered = toml::to_string_pretty(&config)?;
    std::fs::write(output, rendered)
        .with_context(|| format!("failed to write host config {}", output.display()))?;
    println!("Wrote {}", output.display());
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input.to_string())
    }
}

fn prompt_path(label: &str, default: &str) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(prompt(label, default)?))
}

fn prompt_subnets(label: &str, default: &str) -> Result<Vec<String>> {
    let raw = prompt(label, default)?;
    let subnets = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !subnets.is_empty(),
        "{label} must include at least one CIDR"
    );
    Ok(subnets)
}
