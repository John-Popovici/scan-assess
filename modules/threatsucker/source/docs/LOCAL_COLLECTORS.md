# Local Collectors

ThreatSucker does not edit or own DNScap, Enumeros, or SafeSniff. It reads their output files.

The tools are optional. ThreatSucker should keep working when none of them are installed, as long as stored output files can be provided later.

## DNScap

DNScap provides DNS observations. ThreatSucker uses these to decide whether URL/domain indicators matter locally.

Expected DNScap CSV columns:

```text
ts,host,os,interface,src_ip,dst_ip,src_port,dst_port,proto,qname,qtype
```

Import or highlight:

```bash
threatsucker import-dnscap /path/to/dnscap/log/root --replace
threatsucker highlight-dnscap
threatsucker highlight-dnscap --dns /path/to/dns.csv
```

Outputs:

- `data/mini/current/dnscap_highlights.md`
- `data/mini/current/dnscap_highlights.csv`
- `data/mini/current/dnscap_highlights.jsonl`

Important boundary:

> A DNS lookup is evidence of a lookup, not proof of compromise or credential entry.

## Enumeros

Enumeros provides host, browser, OS, software, and network discovery facts.

Preferred workflow:

1. Run Enumeros on the relevant Windows/macOS/Linux host.
2. Save/send the JSON output.
3. Import or filter the stored JSON in ThreatSucker.

Commands:

```bash
threatsucker import-enumeros /path/to/enumeros-output.json
threatsucker filter-enumeros /path/to/enumeros-output.json
threatsucker filter-enumeros /path/to/directory/of/jsons
```

Optional same-host live run:

```bash
threatsucker run-enumeros /path/to/enumeros
```

Stored JSON is preferred because NGOs may collect from multiple platforms.

## SafeSniff

SafeSniff JSON can be imported as local network and exposed-service context:

```bash
threatsucker import-safesniff /path/to/safesniff-output.json
```

ThreatSucker currently treats SafeSniff as another source of local asset/service facts.
