# scan-assess

A local framework that runs security collection modules, passes their JSON outputs to a local OpenAI-compatible LLM endpoint, and writes a Markdown security report.

## Run The LLM Server

Optionally, with llama.cpp, in one terminal:

```bash
./launch_llama.sh
```

The scanner expects an OpenAI-compatible endpoint at:

```text
http://localhost:8033/v1
```

## Run scan-assess

Install dependencies:

```bash
uv sync
```

Official/live path:

```bash
uv run python -m src.scan_assess --live
```

Demo path, including the bundled phishing-DNS scenario and demo ThreatSucker intel:

```bash
uv run python -m src.scan_assess --demo
```

Official run with real DNScap logs:

```bash
uv run python -m src.scan_assess --live --dnscap-log-root /path/to/dnscap/logs
```

Reports are written to `reports/`. Module outputs are written to `outputs/`.

## Imported Modules

- `modules/enumeros`: live local host/software/browser inventory.
- `modules/safesniff`: conservative target detection by default; active scans require opt-in.
- `modules/dnscap`: DNScap DNS log importer.
- `modules/threatsucker`: explainable threat-intel correlation over module outputs.

## ThreatSucker UI

```bash
cd modules/threatsucker/source
uv run threatsucker web --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765/config
```

The config UI provides source toggles, source import, scoring sliders, YAML validation, and raw YAML editing.

## Safety Notes

- Bundled phishing DNS logs are only used by `--demo` or when explicitly passed with `--dnscap-log-root`.
- Bundled demo ThreatSucker intel is excluded from official scan-assess runner workspaces unless `--demo` or `--include-demo-threat-intel` is used.
- Prompting is provenance-aware: sample/demo data is excluded from action items, imported DNS logs are treated as historical observations, and SafeSniff target detection is not described as a TCP service scan.
