# SafeSniff Multi-Platform Build Notes

SafeSniff is a Rust collector and is intended to be built for multiple platforms.

This project-local import includes:

- the vendored SafeSniff Rust source under `source/`
- release binaries under `bin/` for macOS ARM64, macOS x64, Linux ARM64, Linux x64, and Windows x64
- a scan-assess runner that uses the matching binary when present
- a `cargo run` fallback when a platform-specific binary is not present

The runner selects the correct binary automatically from the current OS and CPU architecture.

To rebuild project-local binaries, build from `modules/safesniff/source` and copy the resulting executable into `modules/safesniff/bin/` using one of these names:

- `safesniff-macos-arm64`
- `safesniff-macos-x64`
- `safesniff-linux-arm64`
- `safesniff-linux-x64`
- `safesniff-windows-x64.exe`

The current binaries were built from the vendored source in this repository. macOS targets were built with local Cargo, Linux targets were built in Docker, and Windows x64 was built with the installed MinGW Rust target/toolchain.
