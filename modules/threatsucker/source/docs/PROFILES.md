# Profiles

ThreatSucker ships with the Luxembourg NGO profile as the default:

```text
config/profiles/luxembourg_ngo.yaml
```

Profiles are intended to be changed. The NGO profile is a default installation posture, not a hard-coded assumption.

## What A Profile Controls

A mini profile controls:

- Country and regional terms.
- Sector terms.
- Brand terms.
- Threat focus.
- High-impact indicator types.
- Source allowlist.
- Theme rules used for traceability.
- Output limits.

Theme rules are especially important because reports expose which rule retained an item.

Example rule shape:

```yaml
theme_rules:
  - id: credential_phishing
    label: Credential phishing and account takeover
    threat_focus:
      - phishing
      - credential_theft
    terms:
      - login
      - microsoft
      - microsoft 365
    suggested_ai_use: Treat as awareness, mailbox, browser-history, and DNS-review context.
```

## Creating Another Profile

Copy the default:

```bash
cp config/profiles/luxembourg_ngo.yaml config/profiles/my_profile.yaml
```

Run:

```bash
threatsucker mini run --profile my_profile
```

## Design Rule

Do not hide matching logic in prose. If the chatbot should know why an item was retained, put that reason in profile rules or local evidence records.
