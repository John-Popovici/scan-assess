# Testing dnslog-agent

This file records the practical validation flow used during development.

## Local Commands

Format and test:

```sh
cargo fmt
cargo test
```

Validate a config:

```sh
./target/release/dnslog-agent validate-config --config config.example.toml
```

List capture interfaces:

```sh
./target/release/dnslog-agent interfaces
```

## Continuous Host/Client Test

Start the host collector and local capture on the host machine:

```sh
sudo ./dist/dnslog-agent-aarch64-apple-darwin run --config config.host-test.toml
```

For real deployments, use `configure-host` or a hand-authored config instead of the local test config:

```sh
./dist/dnslog-agent-aarch64-apple-darwin configure-host --output host.config.toml
```

Start a Linux ARM64 client, for example a Kali VM on Apple Silicon:

```sh
cd ~/Desktop
sudo ./dnslog-agent-aarch64-unknown-linux-gnu run --config ./config.kali-client-test.toml
```

Generate DNS in another terminal:

```sh
for d in example.com openai.com cloudflare.com theguardian.com wikipedia.org rust-lang.org github.com apple.com microsoft.com dns.google mozilla.org debian.org kali.org kernel.org ietf.org iana.org fastly.com akamai.com ubuntu.com spotify.com; do
  echo "lookup $d"
  dig "$d" A +short >/dev/null
  dig "$d" AAAA +short >/dev/null
  dig "$d" HTTPS +short >/dev/null
  nslookup "$d" >/dev/null 2>&1
done
```

Start a Windows x64 client from Administrator PowerShell:

```powershell
C:\Users\user\Desktop\dnslog-agent-x86_64-pc-windows-gnu.exe run --config C:\Users\user\Desktop\config.windows-client-test.toml
```

Generate DNS in another Administrator PowerShell:

```powershell
$Domains = @(
  "example.com",
  "openai.com",
  "cloudflare.com",
  "theguardian.com",
  "wikipedia.org",
  "rust-lang.org",
  "github.com",
  "apple.com",
  "microsoft.com",
  "dns.google"
)

foreach ($d in $Domains) {
  nslookup $d | Out-Null
  Resolve-DnsName $d -Type A -ErrorAction SilentlyContinue | Out-Null
  Resolve-DnsName $d -Type AAAA -ErrorAction SilentlyContinue | Out-Null
}
```

## Expected Host Output

The host writes its own local capture and remote client logs:

```text
logs-host-test/
  localhost/YYYY/MM/DD/health.jsonl
  remotehost-kali-linux-2025-2-10-211-55-5/YYYY/MM/DD/dns.jsonl
  remotehost-windows-vm-10-211-55-4/YYYY/MM/DD/dns.jsonl
```

Timestamps in JSON Lines files are UTC RFC3339 values ending in `Z`. Use `--format csv` to produce the old `dns.csv` and `health.csv` files.

## Proven VM Matrix

The following development smoke tests were completed:

- macOS ARM64 host collector, listening on `0.0.0.0:53530`.
- Kali Linux ARM64 client on Parallels, forwarding encrypted DNS events to the macOS host.
- Windows x64 client on Parallels, using Npcap and forwarding encrypted DNS events to the macOS host.

Client-to-host forwarding uses AES-256-GCM with the configured `shared_token` as pre-shared secret material. The LAN wire frame contains `version`, `alg`, `nonce`, and `ciphertext`; DNS event contents are not sent in plaintext.

## Common Pitfalls

- Use `run` for continuous host/client operation. `once --seconds ...` is only for bounded tests.
- Backgrounding `sudo` before credentials are cached can suspend the agent on Linux. Run `sudo -v` first or run the client in the foreground.
- Windows requires Npcap. If `$LASTEXITCODE` is `-1073741515`, a required DLL such as `wpcap.dll` is missing.
- Client and host must use the same `shared_token`; otherwise encrypted frames cannot decrypt.
- `collector_addr` can be an IP address or a resolvable LAN hostname such as `dnslog-host.local:53530`.
