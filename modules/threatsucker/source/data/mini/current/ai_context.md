# ThreatSucker Mini Context

Generated: 2026-05-27T08:28:02.134523+00:00
Profile: Luxembourg NGO Mini Profile (luxembourg_ngo)
Mode: mini/basic, no scoring

## Purpose

This pack contains compact, profile-matched threat information for an AI assistant. Items are included because they match simple profile terms or high-impact categories; no numeric scoring or local personalization has been applied.

## Profile Focus

- Threats: phishing, credential_theft, invoice_fraud, donation_page_impersonation, malware, c2, vulnerability
- Brands/themes: microsoft 365, microsoft, office 365, paypal, docusign, stripe, bgl bnp paribas, post luxembourg
- Regional terms: luxembourg, luxembourgish, luxemburgish, luxembourg ngo, lu, .lu

## Included Threat Items

### url: https://login-example-ngo-support.lu/microsoft365/session

- Kind: indicator
- Source: misp_osint
- Value: https://login-example-ngo-support.lu/microsoft365/session
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login, microsoft, microsoft 365; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: ngo; brand_term: microsoft 365, microsoft
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/local_misp_dns_hit.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### url: https://login-example-ngo-support.lu/microsoft365/session

- Kind: indicator
- Source: misp_osint
- Value: https://login-example-ngo-support.lu/microsoft365/session
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login, microsoft, microsoft 365; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: ngo; brand_term: microsoft 365, microsoft
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/misp_event_sample.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: paypal-invoice-confirmation-portal.com

- Kind: indicator
- Source: misp_osint
- Value: paypal-invoice-confirmation-portal.com
- Filtering rules used: donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice, payment, paypal; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg; sector_term: invoice, payment; brand_term: paypal
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/critical_dns_match_campaign.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: office365-password-reset-verify.com

- Kind: indicator
- Source: misp_osint
- Value: office365-password-reset-verify.com
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: password, office 365; scope: profile relevance); donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg; sector_term: invoice; brand_term: office 365
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/critical_dns_match_campaign.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: login-micros0ft-security.com

- Kind: indicator
- Source: misp_osint
- Value: login-micros0ft-security.com
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login, microsoft, microsoft 365; scope: profile relevance); donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg; sector_term: invoice; brand_term: microsoft 365, microsoft
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/critical_dns_match_campaign.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: invoice-bgl-secure.lu

- Kind: indicator
- Source: misp_osint
- Value: invoice-bgl-secure.lu
- Filtering rules used: donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice, bgl bnp paribas; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: invoice; brand_term: bgl bnp paribas
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/demo_invoice_fraud_event.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: docusign-lu-review.net

- Kind: indicator
- Source: misp_osint
- Value: docusign-lu-review.net
- Filtering rules used: donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice; scope: profile relevance); document_signing_lure (Document-signing and cloud workflow lures; matched: docusign; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu; sector_term: invoice; brand_term: docusign
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/demo_invoice_fraud_event.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### url: https://secure-paypal-donation.example.org/login

- Kind: indicator
- Source: phishtank_verified
- Value: https://secure-paypal-donation.example.org/login
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login; scope: profile relevance); donation_payment_fraud (Donation, payment, and invoice fraud; matched: donation, paypal; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: phishing; threat_focus: credential_theft; sector_term: donation; brand_term: paypal
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/phishtank/phishtank_lookup_sample.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### url: https://invoice-bgl-secure.lu/payments/review

- Kind: indicator
- Source: misp_osint
- Value: https://invoice-bgl-secure.lu/payments/review
- Filtering rules used: donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice, payment; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: invoice, payment
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/demo_invoice_fraud_event.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: secure-sharepoint-document-login.com

- Kind: indicator
- Source: misp_osint
- Value: secure-sharepoint-document-login.com
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login; scope: profile relevance); donation_payment_fraud (Donation, payment, and invoice fraud; matched: invoice; scope: profile relevance); document_signing_lure (Document-signing and cloud workflow lures; matched: document, sharepoint; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg; sector_term: invoice
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/critical_dns_match_campaign.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: login-example-ngo-support.lu

- Kind: indicator
- Source: misp_osint
- Value: login-example-ngo-support.lu
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: ngo
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/local_misp_dns_hit.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### domain: login-example-ngo-support.lu

- Kind: indicator
- Source: misp_osint
- Value: login-example-ngo-support.lu
- Filtering rules used: credential_phishing (Credential phishing and account takeover; matched: login; scope: profile relevance)
- Inclusion reasons: high_impact_indicator_type: domain; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg, lu, .lu; sector_term: ngo
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/misp_event_sample.json
- Suggested AI use: Use as phishing or credential-theft context for Luxembourg NGO awareness and mailbox/DNS review.

### cve: CVE-2024-3094

- Kind: indicator
- Source: misp_osint
- Value: CVE-2024-3094
- Filtering rules used: none
- Inclusion reasons: high_impact_indicator_type: cve; threat_focus: phishing; threat_focus: credential_theft; country_term: luxembourg
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/misp/misp_event_sample.json
- Suggested AI use: Use as vulnerability context mentioned by a source; verify against real affected software before advising action.

### Demo Chrome browser remote code execution vulnerability

- Kind: vulnerability
- Source: circl_vulnerability_lookup
- Value: CVE-2026-12345
- Filtering rules used: none
- Inclusion reasons: threat_focus: vulnerability; impact_signal: exploit_available; impact_signal: known_exploited; impact_signal: cvss 9.1
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/vulnerability_lookup/vulnerability_lookup_sample.jsonl
- Suggested AI use: Use as general vulnerability context; only personalize if matching asset/software data is supplied later.

### url: http://updates-lu-check.example.net/chrome-update.exe

- Kind: indicator
- Source: urlhaus_online
- Value: http://updates-lu-check.example.net/chrome-update.exe
- Filtering rules used: malware_delivery_watchlist (Malware delivery seen in the wild; matched: exe, loader, malware; scope: broad context only)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: malware; country_term: lu
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/urlhaus/urlhaus_sample.jsonl
- Suggested AI use: Use as malware-delivery context; only escalate if later local telemetry observes the domain or URL.

### Example OpenSSL test vulnerability

- Kind: vulnerability
- Source: circl_vulnerability_lookup
- Value: CVE-2024-9999
- Filtering rules used: none
- Inclusion reasons: threat_focus: vulnerability; impact_signal: exploit_available; impact_signal: cvss 8.8
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/vulnerability_lookup/vulnerability_lookup_sample.jsonl
- Suggested AI use: Use as general vulnerability context; only personalize if matching asset/software data is supplied later.

### url: http://malware-drop.example.net/payload.exe

- Kind: indicator
- Source: urlhaus_online
- Value: http://malware-drop.example.net/payload.exe
- Filtering rules used: malware_delivery_watchlist (Malware delivery seen in the wild; matched: exe, loader, malware; scope: broad context only)
- Inclusion reasons: high_impact_indicator_type: url; threat_focus: malware
- Evidence: /Users/user/codeprojects/scan-assess-gui/modules/threatsucker/source/data/raw/urlhaus/urlhaus_sample.jsonl
- Suggested AI use: Use as malware-delivery context; only escalate if later local telemetry observes the domain or URL.

## Excluded Material

0 candidate items were omitted by the output limit or profile filtering.

## Important Boundary

This mini pack is not a decision, risk score, or attribution claim. It is source/context material for a later AI reasoning step.
