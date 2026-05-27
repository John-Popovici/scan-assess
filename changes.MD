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
  - Treats DNScap as a Rust background collector with multi-platform binaries under `modules/dnscap/bin/`; scan-assess does not start packet capture, and the Python runner records the matching collector binary for the current platform.
  - Owns temporal import selection in `modules/dnscap/config/scan_assess_runtime.json`, supporting all stored logs, last day/week/month/year, since last successful scan-assess DNScap import, and custom start/end windows.
  - Added sample DNScap test logs under `modules/dnscap/sample_logs/localhost/2026/05/02/`.
  - Added imported DNScap-style DNS logs under `modules/dnscap/imported_logs/` for report-quality testing with suspicious historical DNS evidence.

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

- `modules/sitechecker/`
  - Added a project-local owner-authorized website exposure checker based on the supplied `/agentic/inputs/site-checker` concept, with malformed source cleaned into a scan-assess runner module.
  - Added `runner.py` so scan-assess writes `sitechecker/sitechecker.json` for a single configured website, defaulting to `https://eastlondonaudio.com`.
  - Added module-local runtime config at `modules/sitechecker/config/scan_assess_runtime.json` so the target website and enabled checks can be changed without adding top-level scan-assess launch arguments.
  - Added low-impact checks for HTTPS posture, security headers, cookie flags, same-site crawl exposure, login/forms/email signals, common exposure paths such as `.env`, `.git/HEAD`, `phpinfo.php`, `server-status`, WordPress login/admin paths, and simple legacy-version heuristics.
  - Added an editable `config/version_policy.json` baseline so detected component versions are compared against operator-maintained minimum-supported versions before falling back to legacy-major heuristics.
  - Added provenance metadata stating the module is a live, single-website, owner-authorized HTTP observation and not an exploit attempt.
  - Added a local Flask controls page for changing the target URL, turning the module on/off, toggling individual checks, running a one-off check, and running an isolated validation suite.
  - Added a validation suite that spins up a local vulnerable sample site and checks that missing headers, exposed `.env`, legacy jQuery, reachability, and login-surface evidence are detected.
  - Added embedded workbench controls so module web UIs such as SiteChecker can be started and opened inside the Modules page instead of only being shown as a command/link.

## Deliberately Not Imported

- `scan-assess-quiz` was ignored per request.

## Notes

- SafeSniff's imported runner is conservative by default; it detects the likely scan target but does not run a network scan unless explicitly enabled.
- Enumeros is a live local collector and includes local network discovery in its current implementation.
- DNScap is integrated as a log importer rather than a live packet capture runner. Live capture often requires elevated privileges and host-specific packet capture dependencies.
- `scan-assess` now has explicit run paths:
  - `python main.py --demo` enables the bundled phishing-DNS demo logs and bundled demo ThreatSucker intel.
  - `python main.py --live` is the official/default path and disables bundled demo ThreatSucker intel.
- CLI parsing now lives in `main.py`; `src/scan_assess.py` exposes callable runner logic and no longer owns argparse setup.
- Module-specific configuration now lives inside each module directory rather than expanding the top-level scan-assess launch arguments. DNScap runtime import settings are stored under `modules/dnscap/config/scan_assess_runtime.json`, and ThreatSucker runtime settings are stored under `modules/threatsucker/config/scan_assess_runtime.json`.
- DNScap temporal controls are module-owned rather than scan-assess CLI arguments. The scan-assess runner reads the configured DNScap window from the DNScap module at run time and records that provenance in reports/manifests.
- Bundled phishing DNS lookups live under `modules/dnscap/imported_logs/` and are only used automatically by `--demo` or when the DNScap module config points at them.
- Bundled demo ThreatSucker feed items are excluded from scan-assess runner workspaces unless `--demo` is used or `modules/threatsucker/config/scan_assess_runtime.json` enables them.
- ThreatSucker source normalization no longer falls back to fixture files unless a source mode explicitly contains `fixture`.
- The LLM prompt now instructs reports to respect provenance, exclude sample/demo data from action items, and avoid describing target-detection-only output as a service scan.
- The LLM prompt now explicitly tells the model that SafeSniff `target_detection_only`, `active_network_scan=false`, or `total_tcp_connect_attempts_planned=0` means no TCP service scan was run, even if the selected profile name is `thorough`.
- The LLM prompt now asks suspicious DNS findings to be classified by likely threat type, such as phishing, credential theft, brand impersonation, or invoice fraud, while still stating that DNS logs alone do not prove compromise.
- Suspicious DNS report guidance now asks the model to name the domains, identify the affected host when available, and recommend concrete follow-up steps such as checking browser history, warning the user, blocking domains, and reviewing credentials.
- Added ThreatSucker runtime dependencies to `pyproject.toml` so the vendored correlation module can run inside scan-assess.

## GUI Workbench Branch

- Added NiceGUI as the local GUI framework dependency.
- Added prompt profiles under `config/prompt_profiles/` so system/user prompts can be viewed, edited, validated, and swapped for demo or live runs.
- Added scenario packs under `config/scenarios/` so demo/live setups can define run mode, DNScap log root, ThreatSucker config set, prompt profile, and expected findings.
- Added LLM profiles under `config/llm_profiles/` so local llama.cpp and online OpenAI-compatible API endpoints can be selected without hardcoding model settings in `scan_assess.py`.
- Added CLI support for `--prompt-profile`, `--scenario`, and `--llm-profile`.
- Added per-run `run_manifest.json` files in output directories so the GUI can connect reports back to prompt profile, scenario, module information, and evidence files.
- Added `src/gui_app.py`, a NiceGUI workbench with run controls, prompt-profile editing, scenario inspection, loaded-module visibility, report browsing, and pretty JSON evidence viewing.
- Split Reports and Evidence into separate GUI tabs. Reports now has pride of place and links into the Evidence browser.
- Updated Evidence to browse module output folders under `outputs/<run>/<module>/`, including historical module folders from previous runs, and to display JSON, JSONL, and text-like evidence in a beautified viewer.
- Imported prior generated run history from the original worktree into this GUI worktree's ignored `outputs/` and `reports/` directories so report/evidence browsing can be tested without running scans.
- Updated the workbench so detected modules can be enabled or disabled per run; disabled modules are skipped by the runner and recorded in module runner information.
- Replaced the separate Prompts/Test Lab split with a bottom-nav Prompt Developer view. Prompt Developer shows the selected scenario, editable system/user prompt, prompt validation, per-module test choices, evidence mix, and run-again button together.
- Removed user-facing Demo/Live mode labels from the GUI; the CLI flags remain internal run-path implementation details.
- Reworked the GUI shell to use a fixed viewport app layout with a visible top navigation bar and contained scroll panels instead of rendering as a long page in browser/PDF output.
- Added an editable Prompt Developer evidence payload. `Run Prompt Check` now writes that JSON to an output run and sends it to the LLM, so prompt tests can deliberately adjust the evidence used to trigger findings.
- Prompt Developer evidence payloads no longer include scenario names, expected-findings labels, demo labels, or fixture markers; the LLM receives only the operator-supplied module-style evidence files.
- Per-module Prompt Developer choices now regenerate the editable evidence JSON, so the visual choices and the LLM-facing payload stay connected while still allowing manual JSON edits.
- Folded run setup and detected-module controls in the GUI sidebar so Prompt Developer has more working space. LLM profile selection now includes editable profile name, model, base URL, API-key environment variable, description, and a save action.
- Updated demo scenario prompting so the LLM is not told that the scenario is a demo; the GUI keeps demo/live labels outside the prompt so scenarios can test analyst behavior.
- Added source evidence improvements for scenario 1: phishing-style DNS lookups, matching threat-intel correlation, and an outdated Chrome browser vulnerability matched to `office-laptop-01`.
- Updated the Reports page so selecting a report now shows a visible contextual-information panel with the linked run, prompt/LLM metadata, input evidence files, supporting run files, and buttons that jump directly into the Evidence browser.
- Tightened report rendering in the GUI so report headings and body text fit the workbench layout more like an operator console instead of oversized document typography.
- Removed the left Run Controls rail from the operator-facing GUI. Scan controls now live in Reports, LLM/profile controls live in a dedicated LLM Setup tab, and detected module enable/disable controls live in a dedicated Modules tab.
- Disabled `example_module` by default in the GUI module selection so the normal operator path starts from the real imported modules.
- Added dark mode as the default GUI theme with a header toggle back to light mode, and tightened the Reports scan-control layout to prevent fields from overhanging their containers.
- Disambiguated LLM profile management in the GUI: profiles can now be loaded into the editor, explicitly activated for runs, saved, saved as new profiles, or deleted as separate actions.
- Fixed Evidence Browser tree population by updating the NiceGUI tree `nodes` prop directly and expanding module folders for the selected run.
- Switched human-facing run/report timestamps in the GUI to European/Luxembourg display format while keeping UTC filenames as stable run IDs.
- Added report and run-manifest provenance for the device that generated each assessment, including hostname and platform, and surfaced that in the Reports contextual information panel.
- Added heuristic module settings-surface detection in the Modules page. ThreatSucker now shows its detected local controls page, launch command, local URL, and config surfaces; modules without a declared surface show that no settings page was detected.
- Added a managed Modules-page launcher for detected web controls. ThreatSucker can now be started from the GUI for config editing, opened in a new tab, and stopped again when the workbench launched it.
- Added SiteChecker to the Modules settings-surface launcher so its website target, check toggles, and validation page can be opened from the workbench.
- Added a ThreatSucker-native validation page and `/api/validation` endpoint. It runs an isolated correlation suite covering DNS threat matching, allowlist suppression, and browser vulnerability inventory matching without mutating live evidence.
- Tightened ThreatSucker allowlist handling so allowlisted domains are forced to archive priority even when other scoring boosts would otherwise lift them back into actionable findings.
- Constrained the Reports page layout so the report/context panels end before the viewport edge and scroll internally, making the card boundary visually clear.
- Condensed the Reports scan settings area so reports remain centre stage. The prompt selector stays readable, output paths are compact, and the run log no longer reserves visible space on the normal report view.
- Renamed generated report metadata to `Run Parameters and Provenance` and added enabled-module selection to both the report metadata and run manifest.
- Fixed the Evidence Browser layout so the module tree and selected evidence viewer are constrained to the viewport and scroll internally. Evidence trees now expand only to the module level by default so large ThreatSucker workspaces do not hide the other module outputs.
- Updated DNScap to behave as a background-collector import module. The DNScap module owns its import window, with all stored logs as the default and module-local settings for last day, last week, last month, last year, since last scan, or a custom date range.
- Added DNScap folder and import-period controls to Reports scan settings, with the chosen folder/window recorded in generated reports and `run_manifest.json`.
- Updated the GUI to persist DNScap import controls into DNScap's module-local runtime config before a run, keeping the module plug-in interface generic.
- Moved DNScap import-window controls out of Reports and into the Modules page, so Reports stays focused on assessment output.
- Added an optional DNScap last-run marker. It is off by default; when enabled, DNScap can import only DNS events after the previous run marker and then update the marker after a successful import.
- Added a pre-run Reports context estimate that uses the selected prompt, active LLM profile context size, enabled modules, and DNScap's configured log/window to estimate whether the assessment will fit before it is sent to the LLM.
- Reworked Prompt Developer into a Prompt Testbench. It now includes a background-evidence selector from previous runs, an explicit Evidence Generator for per-module positives, an evidence-mix summary, and a final editable JSON payload before the LLM receives it.
- Renamed Prompt Testbench to Validation and replaced module evidence choices with consistent severity-style validation cases: off, nominal telemetry, low-confidence issue, and high-confidence actionable issue. Enumeros and SafeSniff validation payloads now exercise richer OS/version, exposed-service, device-inventory, and high-risk service findings.
- Made the default prompt profile NGO-specific for a small Luxembourg NGO with 3 employees and an approximately EUR 1.7m budget, with guidance to keep recommendations proportionate for a small team.
- Tightened the default prompt format so every finding must begin with an explicit `Scope:` label, making local-vs-observed-device provenance harder for the LLM to skip.
- Added saveable validation test suites under `config/test_suites/`. The first suite, `full-validation`, combines phishing DNS, outdated browser evidence, SafeSniff high-risk service exposure, ThreatSucker correlation, and generated background noise.
- Added a Validation background-noise slider so prompt checks can include many benign module-style files and test whether the LLM separates signal from ordinary telemetry. The default full suite uses 30 generated noise files, with the slider able to go higher for stress tests.
- Revamped Validation so the LLM output is the main review panel. Prompt editors are larger and scroll internally, while raw evidence editing has moved to Evidence Generator.
- Added explicit Save Suite / Suite name controls so validation mixes can be saved, reloaded, and reused as named prompt test suites.
- Enlarged the Evidence Generator editor area so generated JSON remains usable as a review/edit surface.
- Validation runs now set `SCAN_ASSESS_RUN_PURPOSE=validation`, record that purpose in `run_manifest.json`, and add validation context to report metadata.
- Reports hides validation reports by default; operators can opt in with `Show validation reports`, where they are clearly labelled `VALIDATION`.
- Added visible Validation run feedback so operators can see when the selected LLM is actively processing a prompt check.
- Removed LLM-facing noise labels from generated validation evidence. Benign filler evidence now appears as ordinary module observations such as resolver observations, asset inventory, and permitted service inventory; the GUI still tracks the slider as background noise internally.
- Locked default prompt fields are now read-only rather than disabled, so operators can still scroll through the system/user prompt text.
- Reports scan settings now label the date/window controls as DNScap-specific because DNScap imports ongoing historical logs while other modules run at assessment time.
- Added LLM profile context-size settings and local llama.cpp launch metadata, including model path, server binary, host, and port.
- Added LLM Setup controls to start/stop a GUI-launched local llama.cpp server and show endpoint health.
- Added a Validation context estimate that compares the selected prompt/evidence mix against the active LLM profile's configured context size and blocks runs that are predictably too large.
- Added `docs/GUI_PLAN.md` to capture the GUI workbench direction and next slice.
