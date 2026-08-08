# Skills index — Bug Bounty Pro

All skills the agent can load, grouped by source. Prefer `methodology/` + `ttp-derived/`;
use `vendor/` for depth on specific vuln classes.

## .claude/skills/ — operating & command skills
The task protocols and operator commands. The two **protocols** are situational guidelines, not
identities: the one aware session loads whichever fits the task in front of it (see
`OPERATING-MODES.md`).
| Skill | Purpose |
|-------|---------|
| `management-protocol` | Protocol for management-type work — orchestrating sub-agents (write-down/report-up, cap 3), reviewing scope/findings at the two independent-review gates, maintenance, propagation, session bookkeeping |
| `testing-protocol` | Protocol for testing-type work — resume-don't-restart, hunt-deep, coverage ledger, the reporting + control gates, WAF back-off, clean stop |
| `generate-scope` | Compile `approved_TTPs.yaml` + `.scope_lock/` from a scope file (operator-triggered) |
| `add-ttp` | Append a framework-derived, scope-adapted TTP and recompile the wall (operator-approved) |
| `opsec-check` | Verify the protections are actually on before the first request |
| `report` · `verification-packet` | Package a validated finding for submission + the operator verification packet |
| `learning-loop` | Record what a session worked out so the next starts from it |
| `wrap-up` | Clean-stop, session log, HANDOFF/ACTIONS, `check_ops`, sync prep |

## methodology/ — authored for this workspace
| Skill | Purpose |
|-------|---------|
| `recon-and-asset-discovery` | Scope-driven passive + active recon, subdomain/content discovery, JS analysis |
| `web-vulnerability-hunting` | Impact-ordered playbooks for IDOR, SSRF, SQLi, auth/ATO, business logic, XSS-chains |
| `api-and-auth-testing` | REST/GraphQL/JWT/OAuth/SAML, mass assignment, rate-limit & MFA bypass |
| `validation-and-triage` | Safe minimal PoC, false-positive kill, CVSS, payable-vs-informational call |
| `report-writing` | Platform-ready report template + severity/impact framing |
| `program-scope-discipline` | Reading scope/ROE, in-vs-out decisions, STOP-and-ask triggers |
| `proxy-driven-testing` | Working through Caido/Burp: edit captured authenticated requests instead of rebuilding them, search history over re-crawling, proxy evidence trail, context discipline, and the three proxy-specific scope hazards |

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

## vendor/ — vetted third-party packs (permissive license, markdown only)
- `claude-bughunter/` — 70+ web vuln-class knowledge bases (see `vendor/SOURCES.md`).
- More available via `./install-external-skills.sh` (see `EXTERNAL-SKILLS.md`).

> **Deliberate:** vendor/ is kept small. Two packs were vetted on 2026-07-25 and NOT adopted
> (a Kali tool reference and a Burp automation skill) — see `EXTERNAL-SKILLS.md` for the
> reasoning. Adding tool documentation for binaries outside the approved set widens what an
> agent reaches for without widening what it is allowed to run; that gap is not worth opening.
