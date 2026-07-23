# Skills index — Bug Bounty Pro

All skills the agent can load, grouped by source. Prefer `methodology/` + `ttp-derived/`;
use `vendor/` for depth on specific vuln classes.

## methodology/ — authored for this workspace
| Skill | Purpose |
|-------|---------|
| `recon-and-asset-discovery` | Scope-driven passive + active recon, subdomain/content discovery, JS analysis |
| `web-vulnerability-hunting` | Impact-ordered playbooks for IDOR, SSRF, SQLi, auth/ATO, business logic, XSS-chains |
| `api-and-auth-testing` | REST/GraphQL/JWT/OAuth/SAML, mass assignment, rate-limit & MFA bypass |
| `validation-and-triage` | Safe minimal PoC, false-positive kill, CVSS, payable-vs-informational call |
| `report-writing` | Platform-ready report template + severity/impact framing |
| `program-scope-discipline` | Reading scope/ROE, in-vs-out decisions, STOP-and-ask triggers |

## ttp-derived/ — bug-bounty-SAFE subset of your Pentest Execution Framework
| Skill | Purpose |
|-------|---------|
| `passive-recon-and-osint` | Passive/light recon, GitHub/source secrets, metadata, passive web recon |
| `web-content-discovery-and-triage` | Polite fuzzing, vhost/param discovery, WAF fingerprint, secret hunting |
| `web-vulnerability-analysis` | Non-destructive verification, safe scanning, version→CVE |
| `web-app-exploitation-poc` | Minimal non-destructive PoCs for payable web/API bugs |
| `reporting` | Reproducible, CVSS-aligned, redacted-evidence write-ups |

> The noisy/aggressive framework phases (network/AD/privesc/post-ex/persistence/evasion)
> were intentionally **excluded** from this bug-bounty workspace.

## vendor/ — vetted third-party packs (MIT, markdown only)
- `claude-bughunter/` — 70+ web vuln-class knowledge bases (see `vendor/SOURCES.md`).
- More available via `./install-external-skills.sh` (see `EXTERNAL-SKILLS.md`).
