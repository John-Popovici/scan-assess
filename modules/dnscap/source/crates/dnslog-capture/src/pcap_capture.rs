use crate::interface::default_interface_name;
use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use dnslog_core::config::Config;
use dnslog_core::dns_parse::{parse_packet, ParseContext, ParseError};
use dnslog_core::event::{HealthEvent, LogEvent};
use dnslog_core::health::Counters;
use pcap::{Active, Capture, Device};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

pub fn run_capture_loop(
    config: &Config,
    sender: Sender<LogEvent>,
    duration: Option<Duration>,
) -> Result<Counters> {
    let interface = if config.capture.interface == "auto" {
        default_interface_name()?
    } else {
        config.capture.interface.clone()
    };
    let mut capture = open_capture(&interface, config)?;
    let context = ParseContext::new(
        interface,
        config.capture.log_queries,
        config.capture.log_responses,
    );
    let mut counters = Counters::default();
    let start = Instant::now();
    let mut next_health =
        Instant::now() + Duration::from_secs(config.agent.health_interval_seconds);

    loop {
        if duration.is_some_and(|limit| start.elapsed() >= limit) {
            send_health(&sender, &mut counters);
            return Ok(counters);
        }

        match capture.next_packet() {
            Ok(packet) => {
                counters.record_packet();
                match parse_packet(packet.data, &context) {
                    Ok(events) => {
                        counters.record_queries(events.len());
                        for event in events {
                            if sender.try_send(LogEvent::Dns(event)).is_err() {
                                counters.record_drop();
                                if !config.agent.drop_when_full {
                                    warn!("writer queue is full; dropping dns event");
                                }
                            }
                        }
                    }
                    Err(ParseError::Unsupported | ParseError::NotDns) => {
                        debug!("ignored unsupported or non-dns packet");
                    }
                    Err(err) => {
                        counters.record_parse_error();
                        debug!(%err, "failed to parse dns packet");
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(err) => {
                counters.record_parse_error();
                debug!(%err, "pcap read error");
            }
        }

        if Instant::now() >= next_health {
            send_health(&sender, &mut counters);
            next_health =
                Instant::now() + Duration::from_secs(config.agent.health_interval_seconds);
        }
    }
}

fn open_capture(interface_name: &str, config: &Config) -> Result<Capture<Active>> {
    let device = Device::list()
        .context("failed to list capture interfaces")?
        .into_iter()
        .find(|device| device.name == interface_name)
        .with_context(|| format!("capture interface not found: {interface_name}"))?;
    let mut capture = Capture::from_device(device)
        .context("failed to create capture handle")?
        .promisc(false)
        .snaplen(65_535)
        .timeout(1_000)
        .open()
        .with_context(|| format!("failed to open capture interface {interface_name}"))?;
    capture
        .filter(&build_bpf_filter(config), true)
        .context("failed to apply BPF filter")?;
    Ok(capture)
}

fn send_health(sender: &Sender<LogEvent>, counters: &mut Counters) {
    let health = HealthEvent::new(
        counters.captured_packets,
        counters.parsed_dns_queries,
        counters.parse_errors,
        counters.dropped_events,
        sender.len(),
    );
    if sender.try_send(LogEvent::Health(health)).is_err() {
        counters.record_drop();
    }
}

pub fn build_bpf_filter(config: &Config) -> String {
    match (config.capture.capture_udp_53, config.capture.capture_tcp_53) {
        (true, true) => "udp port 53 or tcp port 53".to_string(),
        (true, false) => "udp port 53".to_string(),
        (false, true) => "tcp port 53".to_string(),
        (false, false) => "udp port 53 or tcp port 53".to_string(),
    }
}
