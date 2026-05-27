#[derive(Debug, Default, Clone)]
pub struct Counters {
    pub captured_packets: u64,
    pub parsed_dns_queries: u64,
    pub parse_errors: u64,
    pub dropped_events: u64,
}

impl Counters {
    pub fn record_packet(&mut self) {
        self.captured_packets = self.captured_packets.saturating_add(1);
    }

    pub fn record_queries(&mut self, count: usize) {
        self.parsed_dns_queries = self.parsed_dns_queries.saturating_add(count as u64);
    }

    pub fn record_parse_error(&mut self) {
        self.parse_errors = self.parse_errors.saturating_add(1);
    }

    pub fn record_drop(&mut self) {
        self.dropped_events = self.dropped_events.saturating_add(1);
    }
}
