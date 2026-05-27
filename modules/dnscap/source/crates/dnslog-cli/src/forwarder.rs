use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError};
use dnslog_core::event::{hostname_string, LogEvent};
use dnslog_core::net::{encrypt_envelope, log_event_to_wire, WireEnvelope};
use std::io::{BufWriter, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, warn};

pub struct ForwarderConfig {
    pub collector_addr: String,
    pub token: String,
    pub source_id: String,
}

pub fn run_forwarder(receiver: Receiver<LogEvent>, config: ForwarderConfig) -> Result<()> {
    let source_host = hostname_string();
    let source_id = if config.source_id == "auto" {
        source_host.clone()
    } else {
        config.source_id
    };
    let mut writer: Option<BufWriter<TcpStream>> = None;

    loop {
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(LogEvent::Shutdown) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                if let Some(writer) = &mut writer {
                    let _ = writer.flush();
                }
            }
            Ok(event) => {
                let Some(event) = log_event_to_wire(&event) else {
                    continue;
                };
                if writer.is_none() {
                    writer = connect(&config.collector_addr);
                }
                let envelope = WireEnvelope {
                    source_id: source_id.clone(),
                    source_host: source_host.clone(),
                    event,
                };
                if writer.is_some()
                    && write_envelope(
                        writer.as_mut().expect("writer was checked"),
                        &envelope,
                        &config.token,
                    )
                    .is_ok()
                {
                    continue;
                }

                writer = connect(&config.collector_addr);
                if let Some(active) = &mut writer {
                    if let Err(err) = write_envelope(active, &envelope, &config.token) {
                        warn!(%err, "failed to forward event to collector after reconnect");
                        writer = None;
                    }
                }
            }
        }
    }
}

fn connect(addr: &str) -> Option<BufWriter<TcpStream>> {
    match TcpStream::connect(addr) {
        Ok(stream) => {
            let _ = stream.set_nodelay(true);
            Some(BufWriter::new(stream))
        }
        Err(err) => {
            debug!(%err, %addr, "collector connect failed");
            None
        }
    }
}

fn write_envelope(
    writer: &mut BufWriter<TcpStream>,
    envelope: &WireEnvelope,
    token: &str,
) -> Result<()> {
    let frame = encrypt_envelope(envelope, token)?;
    serde_json::to_writer(&mut *writer, &frame)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}
