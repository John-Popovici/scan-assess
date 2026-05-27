# Enumeros Filtered Findings

Filtered host facts from stored or live Enumeros JSON. These are context items for an AI, not standalone risk decisions.

## os is outdated: installed 21H2 latest 25H2

- Host: USER17D8
- Kind: outdated_software
- Severity hint: high
- Evidence: tests/fixtures/enumeros_windows_sample.json

## edge detected at version 148.0.3967.54

- Host: USER17D8
- Kind: browser_detected
- Severity hint: info
- Evidence: tests/fixtures/enumeros_windows_sample.json

## Enumeros observed open TCP port 53 on 10.211.55.1

- Host: USER17D8
- Kind: open_port
- Severity hint: info
- Evidence: tests/fixtures/enumeros_windows_sample.json

## Enumeros overall status is warnings

- Host: USER17D8
- Kind: summary
- Severity hint: review
- Evidence: tests/fixtures/enumeros_windows_sample.json
