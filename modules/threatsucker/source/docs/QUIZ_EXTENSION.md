# Quiz Context Extension

The quiz or scan-assess data should be added as an extension, not as a new "maxi" mode.

## Goal

The quiz extension should provide local human/organizational context such as:

- User technical confidence.
- Security habits.
- Password manager usage.
- MFA coverage.
- Backup confidence.
- Who handles finance, donations, or sensitive records.
- Whether users are likely to recognize phishing or browser update lures.

## Proposed Input

Stored JSON from the quiz tool:

```json
{
  "org_id": "example-ngo",
  "completed_at": "2026-05-10T12:00:00Z",
  "respondents": 8,
  "signals": {
    "technical_confidence": "low",
    "mfa_coverage": "partial",
    "password_manager_usage": "low",
    "phishing_training_recent": false
  }
}
```

## Proposed Output

The extension should write:

- `data/mini/current/quiz_context.md`
- `data/mini/current/quiz_context.json`
- structured `quiz:*` records inside `deep_evidence.json`

## Boundary

Quiz context should not directly decide risk. It should help the AI interpret local evidence:

- A DNS hit on a phishing domain matters more if users report low confidence and weak MFA.
- A browser vulnerability matters more if browser versions are old and patching responsibility is unclear.
