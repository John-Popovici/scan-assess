#[derive(Debug, Clone, Copy)]
pub enum ServiceTarget {
    Linux,
    Macos,
    Windows,
}

pub fn template(target: ServiceTarget) -> &'static str {
    match target {
        ServiceTarget::Linux => LINUX_SYSTEMD,
        ServiceTarget::Macos => MACOS_LAUNCHD,
        ServiceTarget::Windows => WINDOWS_NOTES,
    }
}

const LINUX_SYSTEMD: &str = r#"[Unit]
Description=dnslog-agent local DNS logging
Documentation=https://example.invalid/dnslog-agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnslog-agent run --config /etc/dnslog/config.toml
Restart=on-failure
RestartSec=5
User=dnslog
Group=dnslog
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/dnslog
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_UNIX
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target

# Suggested config:
# [storage]
# root = "/var/lib/dnslog/logs"
#
# Create the service account and grant capture capability to the binary during install:
#   useradd --system --home-dir /var/lib/dnslog --shell /usr/sbin/nologin dnslog
#   install -d -o dnslog -g dnslog -m 0750 /var/lib/dnslog
#   setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dnslog-agent
"#;

const MACOS_LAUNCHD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.dnslog-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/dnslog-agent</string>
    <string>run</string>
    <string>--config</string>
    <string>/Library/Application Support/dnslog/config.toml</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Library/Application Support/dnslog/dnslog-agent.stdout.log</string>
  <key>StandardErrorPath</key>
  <string>/Library/Application Support/dnslog/dnslog-agent.stderr.log</string>
</dict>
</plist>

<!-- Suggested config storage root:
/Library/Application Support/dnslog/logs
-->
"#;

const WINDOWS_NOTES: &str = r#"Windows service support is planned for a later release.

Suggested paths:
  Binary: C:\Program Files\DnsLog\dnslog-agent.exe
  Config: C:\ProgramData\DnsLog\config.toml
  Logs:   C:\ProgramData\DnsLog\logs

Suggested service display name:
  DnsLog Agent

End-user visibility:
  The service should appear in the Windows Services app as "DnsLog Agent".
  Operators can verify activity by checking the daily health JSON Lines file under:
    C:\ProgramData\DnsLog\logs\YYYY\MM\DD\health.jsonl

Npcap must be installed with permissions that allow this process to capture.
For v1, run from an elevated terminal:
  "C:\Program Files\DnsLog\dnslog-agent.exe" run --config "C:\ProgramData\DnsLog\config.toml"
"#;
