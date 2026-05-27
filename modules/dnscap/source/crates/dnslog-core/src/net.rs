use crate::event::{DnsQueryEvent, HealthEvent, LogEvent};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub source_id: String,
    pub source_host: String,
    pub event: WireEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFrame {
    pub version: u8,
    pub alg: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "lowercase")]
pub enum WireEvent {
    Dns(DnsQueryEvent),
    Health(HealthEvent),
}

impl WireEvent {
    pub fn into_log_event(self) -> LogEvent {
        match self {
            Self::Dns(event) => LogEvent::Dns(event),
            Self::Health(event) => LogEvent::Health(event),
        }
    }
}

pub fn log_event_to_wire(event: &LogEvent) -> Option<WireEvent> {
    match event {
        LogEvent::Dns(event) => Some(WireEvent::Dns(event.clone())),
        LogEvent::Health(event) => Some(WireEvent::Health(event.clone())),
        LogEvent::Shutdown => None,
    }
}

#[derive(Debug, Error)]
pub enum WireCryptoError {
    #[error("failed to serialize wire envelope")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid base64 in wire frame")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("unsupported wire frame")]
    UnsupportedFrame,
    #[error("failed to decrypt wire frame")]
    Decrypt,
    #[error("failed to encrypt wire envelope")]
    Encrypt,
}

pub fn encrypt_envelope(
    envelope: &WireEnvelope,
    shared_token: &str,
) -> Result<WireFrame, WireCryptoError> {
    let key = derive_key(shared_token);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = serde_json::to_vec(envelope)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| WireCryptoError::Encrypt)?;

    Ok(WireFrame {
        version: 1,
        alg: "AES-256-GCM".to_string(),
        nonce: BASE64_STANDARD.encode(nonce),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_frame(
    frame: &WireFrame,
    shared_token: &str,
) -> Result<WireEnvelope, WireCryptoError> {
    if frame.version != 1 || frame.alg != "AES-256-GCM" {
        return Err(WireCryptoError::UnsupportedFrame);
    }
    let nonce = BASE64_STANDARD.decode(&frame.nonce)?;
    if nonce.len() != 12 {
        return Err(WireCryptoError::InvalidNonce);
    }
    let ciphertext = BASE64_STANDARD.decode(&frame.ciphertext)?;
    let key = derive_key(shared_token);
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| WireCryptoError::Decrypt)?;
    serde_json::from_slice(&plaintext).map_err(WireCryptoError::Serialize)
}

fn derive_key(shared_token: &str) -> Key<Aes256Gcm> {
    let digest = Sha256::digest(shared_token.as_bytes());
    *Key::<Aes256Gcm>::from_slice(&digest)
}

pub fn remote_source_dir(source_id: &str, peer_ip: IpAddr) -> String {
    let id = sanitize_component(source_id);
    let ip = sanitize_component(&peer_ip.to_string());
    format!("remotehost-{id}-{ip}")
}

pub fn sanitize_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out.to_string()
    }
}

pub fn ip_allowed(peer: IpAddr, subnets: &[String]) -> bool {
    if subnets.is_empty() {
        return true;
    }
    subnets.iter().any(|subnet| ip_in_cidr(peer, subnet))
}

fn ip_in_cidr(peer: IpAddr, cidr: &str) -> bool {
    let Some((base, prefix)) = cidr.split_once('/') else {
        return peer.to_string() == cidr;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (peer, base.parse::<IpAddr>()) {
        (IpAddr::V4(peer), Ok(IpAddr::V4(base))) => ipv4_in_cidr(peer, base, prefix),
        (IpAddr::V6(peer), Ok(IpAddr::V6(base))) => prefix == 128 && peer == base,
        _ => false,
    }
}

fn ipv4_in_cidr(peer: Ipv4Addr, base: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(peer) & mask == u32::from(base) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_dir_is_filesystem_safe() {
        let dir = remote_source_dir("laptop 01/admin", "192.168.1.44".parse().unwrap());
        assert_eq!(dir, "remotehost-laptop-01-admin-192-168-1-44");
    }

    #[test]
    fn allowed_subnets_match_ipv4_cidr() {
        let allowed = vec!["192.168.1.0/24".to_string()];
        assert!(ip_allowed("192.168.1.44".parse().unwrap(), &allowed));
        assert!(!ip_allowed("192.168.2.44".parse().unwrap(), &allowed));
    }

    #[test]
    fn encrypted_wire_frame_round_trips() {
        let event = HealthEvent::new(1, 1, 0, 0, 0);
        let envelope = WireEnvelope {
            source_id: "host-1".to_string(),
            source_host: "host-1".to_string(),
            event: WireEvent::Health(event),
        };

        let frame = encrypt_envelope(&envelope, "secret-token").unwrap();
        let raw = serde_json::to_string(&frame).unwrap();
        assert!(!raw.contains("host-1"));
        assert!(!raw.contains("health"));

        let decrypted = decrypt_frame(&frame, "secret-token").unwrap();
        assert_eq!(decrypted.source_id, "host-1");
        assert!(decrypt_frame(&frame, "wrong-token").is_err());
    }
}
