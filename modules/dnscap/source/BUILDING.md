# Building dnslog-agent

`dnslog-agent` links against libpcap/Npcap through the Rust `pcap` crate. That is the main build and packaging wrinkle: the binary is small, but each target still needs the right packet-capture headers or import libraries at build time, and the right packet-capture runtime on the host.

For release artifacts, prefer reproducible build environments. In practice:

- Use the native host for macOS artifacts.
- Use Docker for Linux artifacts so libpcap headers are installed in a known environment.
- Use the GNU Windows target with a generated `wpcap.dll` import library, then install Npcap on the Windows host at runtime.

## Local Development Build

```sh
cargo build --release
```

The local development binary is written to:

```text
target/release/dnslog-agent
```

## macOS

Apple Silicon:

```sh
cargo build --release --target aarch64-apple-darwin
```

Intel macOS:

```sh
cargo build --release --target x86_64-apple-darwin
```

Copy the release artifact into `dist/`:

```sh
cp target/aarch64-apple-darwin/release/dnslog-agent dist/dnslog-agent-aarch64-apple-darwin
```

```sh
cp target/x86_64-apple-darwin/release/dnslog-agent dist/dnslog-agent-x86_64-apple-darwin
```

## Linux With Docker

Linux builds need libpcap development headers. The recommended release approach is Docker, because it avoids leaking host-specific library state into the build.

ARM64 Linux:

```sh
docker run --rm \
  -e CARGO_TARGET_DIR=/work/target/linux-aarch64-docker \
  -v "$PWD:/work" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
  -w /work \
  rust:latest \
  bash -lc 'apt-get update && apt-get install -y libpcap-dev pkg-config && /usr/local/cargo/bin/cargo build --release'
```

```sh
cp target/linux-aarch64-docker/release/dnslog-agent \
  dist/dnslog-agent-aarch64-unknown-linux-gnu
```

x86_64 Linux:

```sh
docker run --rm --platform linux/amd64 \
  -e CARGO_TARGET_DIR=/work/target/linux-x86_64-docker \
  -v "$PWD:/work" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
  -w /work \
  rust:latest \
  bash -lc 'apt-get update && apt-get install -y libpcap-dev pkg-config && /usr/local/cargo/bin/cargo build --release'
```

```sh
cp target/linux-x86_64-docker/release/dnslog-agent \
  dist/dnslog-agent-x86_64-unknown-linux-gnu
```

If Docker prints `cargo: command not found`, call Cargo by absolute path inside the container:

```text
/usr/local/cargo/bin/cargo build --release
```

## Windows x64

The GNU Windows build needs a MinGW import library for `wpcap.dll`. Generate it from `build/windows/wpcap.def`:

```sh
mkdir -p build/windows/lib
x86_64-w64-mingw32-dlltool \
  -d build/windows/wpcap.def \
  -l build/windows/lib/libwpcap.a \
  -m i386:x86-64
```

Build the Windows executable:

```sh
RUSTFLAGS='-L native=build/windows/lib' \
  cargo build --release --target x86_64-pc-windows-gnu
```

Copy the release artifact into `dist/`:

```sh
cp target/x86_64-pc-windows-gnu/release/dnslog-agent.exe \
  dist/dnslog-agent-x86_64-pc-windows-gnu.exe
```

The resulting executable still requires Npcap on the Windows host at runtime. Install Npcap from:

```text
https://npcap.com/#download
```

Enable WinPcap API-compatible Mode if the installer offers it. The agent needs Npcap's `wpcap.dll` at runtime. If Windows exits immediately with no output and PowerShell shows:

```powershell
$LASTEXITCODE
-1073741515
```

then a required DLL is missing. Check:

```powershell
Test-Path C:\Windows\System32\Npcap\wpcap.dll
Test-Path C:\Windows\System32\wpcap.dll
```

The MSVC target requires Visual Studio Build Tools and a Npcap SDK/import library on a Windows build runner. The GNU target above is the current recommended path for producing the Windows x64 artifact from macOS/Linux build machines.

## One-Shot Release Refresh

From the repository root, this refreshes the Linux ARM64 and Windows x64 `dist/` artifacts:

```sh
set -euo pipefail

mkdir -p build/windows/lib

x86_64-w64-mingw32-dlltool \
  -d build/windows/wpcap.def \
  -l build/windows/lib/libwpcap.a \
  -m i386:x86-64

docker run --rm \
  -e CARGO_TARGET_DIR=/work/target/linux-aarch64-docker \
  -v "$PWD:/work" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
  -w /work \
  rust:latest \
  bash -lc 'apt-get update && apt-get install -y libpcap-dev pkg-config && /usr/local/cargo/bin/cargo build --release'

cp target/linux-aarch64-docker/release/dnslog-agent \
  dist/dnslog-agent-aarch64-unknown-linux-gnu

RUSTFLAGS='-L native=build/windows/lib' \
  cargo build --release --target x86_64-pc-windows-gnu

cp target/x86_64-pc-windows-gnu/release/dnslog-agent.exe \
  dist/dnslog-agent-x86_64-pc-windows-gnu.exe
```
