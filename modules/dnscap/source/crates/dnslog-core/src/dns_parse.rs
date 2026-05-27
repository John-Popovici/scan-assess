use crate::event::{hostname_string, os_name, DnsQueryEvent};
use chrono::Utc;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ParseContext {
    pub interface: String,
    pub host: String,
    pub os: String,
    pub log_queries: bool,
    pub log_responses: bool,
}

impl ParseContext {
    pub fn new(interface: impl Into<String>, log_queries: bool, log_responses: bool) -> Self {
        Self {
            interface: interface.into(),
            host: hostname_string(),
            os: os_name().to_string(),
            log_queries,
            log_responses,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("packet too short")]
    ShortPacket,
    #[error("unsupported link or network header")]
    Unsupported,
    #[error("malformed packet")]
    Malformed,
    #[error("not dns")]
    NotDns,
    #[error("dns message has no questions")]
    NoQuestions,
}

#[derive(Debug, Clone)]
struct Flow<'a> {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: &'a str,
}

pub fn parse_packet(data: &[u8], context: &ParseContext) -> Result<Vec<DnsQueryEvent>, ParseError> {
    let payload = parse_ethernet(data)?;
    parse_ip_payload(payload, context)
}

pub fn parse_ip_payload(
    data: &[u8],
    context: &ParseContext,
) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.is_empty() {
        return Err(ParseError::ShortPacket);
    }

    match data[0] >> 4 {
        4 => parse_ipv4(data, context),
        6 => parse_ipv6(data, context),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_ethernet(data: &[u8]) -> Result<&[u8], ParseError> {
    if data.len() < 14 {
        return Err(ParseError::ShortPacket);
    }

    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    for _ in 0..2 {
        if matches!(ethertype, 0x8100 | 0x88a8) {
            if data.len() < offset + 4 {
                return Err(ParseError::ShortPacket);
            }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }
    }

    match ethertype {
        0x0800 | 0x86dd => Ok(&data[offset..]),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_ipv4(data: &[u8], context: &ParseContext) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::ShortPacket);
    }
    let ihl = usize::from(data[0] & 0x0f) * 4;
    if ihl < 20 || data.len() < ihl {
        return Err(ParseError::Malformed);
    }
    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_len < ihl || data.len() < total_len {
        return Err(ParseError::ShortPacket);
    }

    let proto = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]).to_string();
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]).to_string();
    parse_transport(proto, &src_ip, &dst_ip, &data[ihl..total_len], context)
}

fn parse_ipv6(data: &[u8], context: &ParseContext) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.len() < 40 {
        return Err(ParseError::ShortPacket);
    }
    let payload_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if data.len() < 40 + payload_len {
        return Err(ParseError::ShortPacket);
    }

    let proto = data[6];
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()).to_string();
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()).to_string();
    parse_transport(
        proto,
        &src_ip,
        &dst_ip,
        &data[40..40 + payload_len],
        context,
    )
}

fn parse_transport(
    proto: u8,
    src_ip: &str,
    dst_ip: &str,
    data: &[u8],
    context: &ParseContext,
) -> Result<Vec<DnsQueryEvent>, ParseError> {
    match proto {
        17 => parse_udp(src_ip, dst_ip, data, context),
        6 => parse_tcp(src_ip, dst_ip, data, context),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_udp(
    src_ip: &str,
    dst_ip: &str,
    data: &[u8],
    context: &ParseContext,
) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::ShortPacket);
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    if src_port != 53 && dst_port != 53 {
        return Err(ParseError::NotDns);
    }
    let length = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if length < 8 || data.len() < length {
        return Err(ParseError::ShortPacket);
    }
    let flow = Flow {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port,
        dst_port,
        proto: "udp",
    };
    parse_dns_message(&data[8..length], flow, context)
}

fn parse_tcp(
    src_ip: &str,
    dst_ip: &str,
    data: &[u8],
    context: &ParseContext,
) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::ShortPacket);
    }
    let data_offset = usize::from(data[12] >> 4) * 4;
    if data_offset < 20 || data.len() < data_offset + 2 {
        return Err(ParseError::Malformed);
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    if src_port != 53 && dst_port != 53 {
        return Err(ParseError::NotDns);
    }

    let tcp_payload = &data[data_offset..];
    let dns_len = usize::from(u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]));
    if tcp_payload.len() < 2 + dns_len {
        return Err(ParseError::ShortPacket);
    }
    let flow = Flow {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port,
        dst_port,
        proto: "tcp",
    };
    parse_dns_message(&tcp_payload[2..2 + dns_len], flow, context)
}

fn parse_dns_message(
    data: &[u8],
    flow: Flow<'_>,
    context: &ParseContext,
) -> Result<Vec<DnsQueryEvent>, ParseError> {
    if data.len() < 12 {
        return Err(ParseError::ShortPacket);
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    if (is_response && !context.log_responses) || (!is_response && !context.log_queries) {
        return Ok(Vec::new());
    }

    let qdcount = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if qdcount == 0 {
        return Err(ParseError::NoQuestions);
    }

    let mut offset = 12;
    let mut events = Vec::with_capacity(qdcount.min(4));
    for _ in 0..qdcount {
        let qname = parse_dns_name(data, &mut offset)?;
        if data.len() < offset + 4 {
            return Err(ParseError::ShortPacket);
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 4;
        events.push(DnsQueryEvent {
            ts: Utc::now(),
            host: context.host.clone(),
            os: context.os.clone(),
            interface: context.interface.clone(),
            src_ip: flow.src_ip.clone(),
            dst_ip: flow.dst_ip.clone(),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            proto: flow.proto.to_string(),
            qname,
            qtype: format_qtype(qtype),
        });
    }

    Ok(events)
}

pub fn parse_dns_name(data: &[u8], offset: &mut usize) -> Result<String, ParseError> {
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if pos >= data.len() {
            return Err(ParseError::ShortPacket);
        }
        let len = data[pos];

        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return Err(ParseError::ShortPacket);
            }
            let ptr = usize::from(u16::from_be_bytes([len & 0x3f, data[pos + 1]]));
            if ptr >= data.len() {
                return Err(ParseError::Malformed);
            }
            if !jumped {
                *offset = pos + 2;
            }
            pos = ptr;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return Err(ParseError::Malformed);
            }
            continue;
        }

        if len & 0xc0 != 0 {
            return Err(ParseError::Malformed);
        }
        pos += 1;
        if len == 0 {
            if !jumped {
                *offset = pos;
            }
            break;
        }
        let len = usize::from(len);
        if len > 63 || pos + len > data.len() {
            return Err(ParseError::ShortPacket);
        }
        let label = &data[pos..pos + len];
        if !label.iter().all(|byte| byte.is_ascii_graphic()) {
            return Err(ParseError::Malformed);
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }

    if labels.is_empty() {
        Ok(".".to_string())
    } else {
        Ok(labels.join("."))
    }
}

pub fn format_qtype(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        other => format!("UNKNOWN({other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qtype_formatting_is_human_readable() {
        assert_eq!(format_qtype(1), "A");
        assert_eq!(format_qtype(28), "AAAA");
        assert_eq!(format_qtype(65), "HTTPS");
        assert_eq!(format_qtype(65280), "UNKNOWN(65280)");
    }

    #[test]
    fn parses_safe_dns_name() {
        let data = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let mut offset = 0;
        assert_eq!(parse_dns_name(&data, &mut offset).unwrap(), "example.com");
        assert_eq!(offset, data.len());
    }

    #[test]
    fn rejects_compression_loop() {
        let data = [0xc0, 0x00];
        let mut offset = 0;
        assert_eq!(
            parse_dns_name(&data, &mut offset),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn malformed_udp_packet_is_error_not_panic() {
        let context = ParseContext::new("en0", true, false);
        assert_eq!(
            parse_ip_payload(&[0x45, 0], &context),
            Err(ParseError::ShortPacket)
        );
    }

    #[test]
    fn parses_udp_dns_query_from_ipv4_packet() {
        let context = ParseContext {
            interface: "en0".to_string(),
            host: "host".to_string(),
            os: "linux".to_string(),
            log_queries: true,
            log_responses: false,
        };
        let mut dns = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        dns.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        let udp_len = (8 + dns.len()) as u16;
        let total_len = 20 + usize::from(udp_len);
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 168, 1, 44]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&55321u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
        packet[28..].copy_from_slice(&dns);

        let events = parse_ip_payload(&packet, &context).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].qname, "example.com");
        assert_eq!(events[0].qtype, "A");
        assert_eq!(events[0].proto, "udp");
    }
}
