# Flask Web Interface

ThreatSucker includes a small optional Flask interface for local operators.

## Install

```bash
pip install -e ".[dev]"
```

Flask is a runtime dependency. DNScap, Enumeros, and SafeSniff are not.

## Run

```bash
threatsucker web
```

Default URL:

```text
http://127.0.0.1:8765
```

Choose another port:

```bash
threatsucker web --port 8080
```

## What It Does

The interface can:

- Build the mini context pack.
- Build the relevance brief.
- Collect live public feeds and rebuild outputs.
- Show collector availability.
- Show an at-a-glance visual overview of devices, services, DNS matches, and SafeSniff exposure.
- Import stored DNScap, Enumeros, or SafeSniff output by local path.
- Link to the human brief and JSON API outputs.

## Optional Collectors

The web UI checks whether these commands are installed on the same machine:

- `dnscap`
- `enumeros`
- `safesniff`

They are optional. ThreatSucker can still read stored output files:

- DNScap DNS CSV or log root.
- Enumeros JSON.
- SafeSniff JSON.

This matters because Windows/macOS/Linux hosts may run Enumeros elsewhere and send JSON back to the ThreatSucker machine.

## JSON Endpoints

```text
/api/brief
/api/deep-evidence
/api/outputs
/api/overview
```

External software should generally prefer `ngo_intel.pipeline`, but these endpoints are useful for a local dashboard or simple integration.

## Boundary

The web UI is a local operator interface, not an internet-facing security portal. Put it behind local access controls if deployed beyond localhost.
