# Changes

## Added Project-Local Module Imports

Imported new project-local versions of the non-quiz input tools from `/Users/user/codeprojects/agentic/inputs` into this repository. The original projects were left untouched.

## Rust Multi-Platform Handling

All imported Rust-based tools are treated as multi-platform collectors.

- Enumeros includes the upstream Linux, macOS, and Windows binaries that were available in its `dist/` folder.
- DNScap includes the upstream Linux, macOS, and Windows binaries that were available in its `dist/` folder.
- SafeSniff did not have a full `dist/` folder in the source project, so release binaries were built from the project-local source for macOS ARM64, macOS x64, Linux ARM64, Linux x64, and Windows x64. Build notes are in `modules/safesniff/BUILDING.md`.

- `modules/enumeros/`
  - Vendored Rust source, README, license, lockfile, and platform binaries.
  - Added `runner.py` so scan-assess can call Enumeros and collect `enumeros.json`.
  - Adds provenance metadata marking output as live local host inventory.
  - Supports overriding the binary with `SCAN_ASSESS_ENUMEROS_BIN`.

- `modules/safesniff/`
  - Vendored Rust source, lockfile, sample report, build notes, and release binaries for macOS ARM64/x64, Linux ARM64/x64, and Windows x64.
  - Added `runner.py` so scan-assess can call SafeSniff and collect `safesniff.json`.
  - Adds provenance metadata distinguishing target-detection-only runs from active TCP service scans.
  - Defaults to `--detect-target` mode to avoid unsolicited network scanning.
  - Falls back to `cargo run` from the vendored source when a platform binary is not present.
  - Set `SCAN_ASSESS_SAFESNIFF_MODE=scan` to run a scan, with optional `SCAN_ASSESS_SAFESNIFF_TARGET`, `SCAN_ASSESS_SAFESNIFF_PROFILE`, and `SCAN_ASSESS_SAFESNIFF_TIMEOUT`.

- `modules/dnscap/`
  - Vendored Rust workspace source, docs, configs, lockfile, and platform binaries.
  - Added `runner.py` that imports existing DNScap `dns.jsonl` or `dns.csv` logs and writes `dnscap_summary.json`.
  - Adds provenance metadata marking bundled logs as sample data and external log roots as imported evidence.
  - Added sample DNScap test logs under `modules/dnscap/sample_logs/localhost/2026/05/02/`.
  - Added imported DNScap-style DNS logs under `modules/dnscap/imported_logs/` for report-quality testing with suspicious historical DNS evidence.
  - Supports overriding the log root with `SCAN_ASSESS_DNSCAP_LOG_ROOT`.

- `modules/threatsucker/`
  - Vendored a clean project-local copy of ThreatSucker / `ngo-intel` without virtualenvs, cache files, old generated mini/scored outputs, or original git metadata.
  - Added `runner.py` so scan-assess can call ThreatSucker as an explainable threat-intel correlation layer after the raw collectors run.
  - The runner uses a per-run ThreatSucker workspace under the current scan output directory, so imported local evidence and generated scoring outputs do not mutate the vendored source copy.
  - The runner imports DNScap, Enumeros, and SafeSniff outputs into ThreatSucker local context, runs normalize/score/agent-brief, and writes `threatsucker_correlation.json`.
  - The runner supports `SCAN_ASSESS_THREATSUCKER_CONFIG_SET` for selecting a named ThreatSucker config set during scan-assess runs.
  - Raw module outputs remain available to the LLM; ThreatSucker adds filtered, scored, explainable correlation rather than hiding the underlying evidence.
  - Added `critical_dns_match_campaign.json`, a demo-only local MISP-style threat feed item designed to match the imported suspicious DNScap evidence and demonstrate critical stop-worthy scoring.
  - Added named config sets under `config_sets/`, seeded with a `default` set that captures the current organisation profile, scoring rules, source config, allowlist, brands, domains, user competency profile, and mini profile config.
  - Added `ngo_intel.config_sets` as the shared config-management layer used by the CLI, web UI, and scan-assess runner.
  - Added CLI config management:
    - `threatsucker config list`
    - `threatsucker config save <name>`
    - `threatsucker config apply <name>`
    - `threatsucker run --config-set <name>`
    - `threatsucker smart run --config-set <name>`
  - Added CLI file override options for run-time config selection: `--org-profile`, `--scoring-rules`, `--source-config`, `--allowlist`, `--brands`, and `--domains`.
  - Updated the Flask web interface with a `Config` page for viewing, editing, saving, applying, and creating named config sets through the same backend used by the CLI.
  - Upgraded the web config editor with a visual scoring-rules workspace: sliders for source weights, relevance boosts, penalties, and priority bands, while keeping the raw YAML editor as the canonical editing surface.
  - Added web YAML validation checks for config files, including scoring-rule structure, integer weights, positive/negative direction checks, and descending priority-band checks. Invalid YAML is blocked on save/apply and can be checked live from the editor.
  - Added a visual threat-source manager to the config page for turning sources on/off, editing source modes, URLs, and collection limits while keeping `config/source_config.yaml` editable as raw YAML.
  - Added web source YAML validation, including checks for `enabled` booleans and numeric source limits.
  - Added source-file import from the config page. Compatible local files/directories are copied into ThreatSucker's `data/raw/<source>/<date>/` tree for MISP OSINT, CIRCL Vulnerability Lookup, PhishTank, and URLhaus.
  - Updated normalization so disabled sources in `config/source_config.yaml` are not fed into scoring, making source toggles meaningful for both live collection and imported raw evidence.
  - Reworked the config page into an operator-focused layout with a compact command bar, task rail, source cards, sensitivity sliders, validation status, and collapsed raw YAML files for advanced editing.
  - Replaced internal source mode labels in the visual UI with operator-friendly labels while preserving the original YAML values.

## Deliberately Not Imported

- `scan-assess-quiz` was ignored per request.

## Notes

- SafeSniff's imported runner is conservative by default; it detects the likely scan target but does not run a network scan unless explicitly enabled.
- Enumeros is a live local collector and includes local network discovery in its current implementation.
- DNScap is integrated as a log importer rather than a live packet capture runner. Live capture often requires elevated privileges and host-specific packet capture dependencies.
- `scan-assess` now has explicit run paths:
  - `python -m src.scan_assess --demo` enables the bundled phishing-DNS demo logs and bundled demo ThreatSucker intel.
  - `python -m src.scan_assess --live` is the official/default path and disables bundled demo ThreatSucker intel.
  - `python -m src.scan_assess --dnscap-log-root /path/to/logs` imports real DNScap logs for a live/official run.
- Bundled phishing DNS lookups live under `modules/dnscap/imported_logs/` and are only used automatically by `--demo` or when explicitly passed as `--dnscap-log-root`.
- Bundled demo ThreatSucker feed items are excluded from scan-assess runner workspaces unless `--demo` or `--include-demo-threat-intel` is used.
- ThreatSucker source normalization no longer falls back to fixture files unless a source mode explicitly contains `fixture`.
- The LLM prompt now instructs reports to respect provenance, exclude sample/demo data from action items, and avoid describing target-detection-only output as a service scan.
- The LLM prompt now explicitly tells the model that SafeSniff `target_detection_only`, `active_network_scan=false`, or `total_tcp_connect_attempts_planned=0` means no TCP service scan was run, even if the selected profile name is `thorough`.
- The LLM prompt now asks suspicious DNS findings to be classified by likely threat type, such as phishing, credential theft, brand impersonation, or invoice fraud, while still stating that DNS logs alone do not prove compromise.
- Suspicious DNS report guidance now asks the model to name the domains, identify the affected host when available, and recommend concrete follow-up steps such as checking browser history, warning the user, blocking domains, and reviewing credentials.
- Added ThreatSucker runtime dependencies to `pyproject.toml` so the vendored correlation module can run inside scan-assess.
