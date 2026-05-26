use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender};
use dnslog_core::config::{CollectorConfig, StorageFormat};
use dnslog_core::event::LogEvent;
use dnslog_core::net::{decrypt_frame, ip_allowed, remote_source_dir, WireFrame};
use dnslog_core::storage::{run_writer, WriterConfig};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{debug, warn};

pub struct CollectorHandle {
    stop: Arc<AtomicBool>,
    join: JoinHandle<Result<()>>,
}

impl CollectorHandle {
    pub fn stop(self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.join
            .join()
            .map_err(|_| anyhow::anyhow!("collector thread panicked"))?
    }
}

pub fn start_collector(
    config: CollectorConfig,
    storage_root: PathBuf,
    flush_interval: Duration,
    retention_days: u64,
    format: StorageFormat,
) -> Result<CollectorHandle> {
    let listener = TcpListener::bind(&config.listen_addr)
        .with_context(|| format!("failed to bind collector listener {}", config.listen_addr))?;
    listener
        .set_nonblocking(true)
        .context("failed to configure collector listener")?;

    let stop = Arc::new(AtomicBool::new(false));
    let writers = Arc::new(Mutex::new(RemoteWriters::new(
        storage_root,
        flush_interval,
        config.max_remote_queue_events,
        config.max_frame_bytes,
        retention_days,
        format,
    )));
    let active_clients = Arc::new(AtomicUsize::new(0));
    let join_stop = Arc::clone(&stop);

    let join = thread::spawn(move || {
        while !join_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let peer_ip = peer.ip();
                    if !ip_allowed(peer_ip, &config.allowed_subnets) {
                        warn!(%peer_ip, "rejected collector client outside allowed subnets");
                        continue;
                    }
                    if active_clients.fetch_add(1, Ordering::Relaxed) >= config.max_clients {
                        active_clients.fetch_sub(1, Ordering::Relaxed);
                        warn!(%peer_ip, "rejected collector client; max clients reached");
                        continue;
                    }
                    let token = config.shared_token.clone();
                    let writers = Arc::clone(&writers);
                    let active_clients = Arc::clone(&active_clients);
                    let read_timeout = Duration::from_secs(config.read_timeout_seconds);
                    thread::spawn(move || {
                        let _guard = ClientGuard(active_clients);
                        if let Err(err) =
                            handle_client(stream, peer_ip, token, read_timeout, writers)
                        {
                            debug!(%err, %peer_ip, "collector client ended");
                        }
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(err) => return Err(err).context("collector accept failed"),
            }
        }
        Ok(())
    });

    Ok(CollectorHandle { stop, join })
}

fn handle_client(
    stream: TcpStream,
    peer_ip: IpAddr,
    token: String,
    read_timeout: Duration,
    writers: Arc<Mutex<RemoteWriters>>,
) -> Result<()> {
    stream
        .set_read_timeout(Some(read_timeout))
        .context("failed to set collector client read timeout")?;
    let mut reader = BufReader::new(stream);
    let max_frame_bytes = writers
        .lock()
        .map_err(|_| anyhow::anyhow!("remote writer map poisoned"))?
        .max_frame_bytes;
    while let Some(line) = read_frame(&mut reader, max_frame_bytes)? {
        let frame: WireFrame =
            serde_json::from_slice(&line).context("failed to parse encrypted collector frame")?;
        let envelope =
            decrypt_frame(&frame, &token).context("failed to decrypt collector frame")?;
        let source_dir = remote_source_dir(&envelope.source_id, peer_ip);
        let event = envelope.event.into_log_event();
        let mut writers = writers
            .lock()
            .map_err(|_| anyhow::anyhow!("remote writer map poisoned"))?;
        writers.send(&source_dir, event)?;
    }
    Ok(())
}

fn read_frame(
    reader: &mut BufReader<TcpStream>,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .context("failed to read collector frame")?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Ok(Some(line));
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        let chunk = &available[..take];
        let frame_bytes = chunk.strip_suffix(b"\n").unwrap_or(chunk);
        let frame_bytes = frame_bytes.strip_suffix(b"\r").unwrap_or(frame_bytes);
        anyhow::ensure!(
            line.len() + frame_bytes.len() <= max_frame_bytes,
            "collector frame exceeded max_frame_bytes"
        );
        line.extend_from_slice(frame_bytes);
        reader.consume(take);

        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

struct ClientGuard(Arc<AtomicUsize>);

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct RemoteWriters {
    root: PathBuf,
    flush_interval: Duration,
    capacity: usize,
    max_frame_bytes: usize,
    retention_days: u64,
    format: StorageFormat,
    senders: HashMap<String, Sender<LogEvent>>,
}

impl RemoteWriters {
    fn new(
        root: PathBuf,
        flush_interval: Duration,
        capacity: usize,
        max_frame_bytes: usize,
        retention_days: u64,
        format: StorageFormat,
    ) -> Self {
        Self {
            root,
            flush_interval,
            capacity,
            max_frame_bytes,
            retention_days,
            format,
            senders: HashMap::new(),
        }
    }

    fn send(&mut self, source_dir: &str, event: LogEvent) -> Result<()> {
        if !self.senders.contains_key(source_dir) {
            let (sender, receiver) = bounded(self.capacity);
            let writer_config = WriterConfig {
                root: self.root.join(source_dir),
                flush_interval: self.flush_interval,
                retention_days: self.retention_days,
                format: self.format,
            };
            thread::spawn(move || {
                if let Err(err) = run_writer(receiver, writer_config) {
                    warn!(%err, "remote writer stopped");
                }
            });
            self.senders.insert(source_dir.to_string(), sender);
        }

        if let Some(sender) = self.senders.get(source_dir) {
            if sender.try_send(event).is_err() {
                warn!(%source_dir, "remote writer queue full; dropping event");
            }
        }
        Ok(())
    }
}
