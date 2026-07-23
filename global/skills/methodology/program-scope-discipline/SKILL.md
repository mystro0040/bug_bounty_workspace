---
name: program-scope-discipline
description: Read and honor a program's scope and rules of engagement — what's in vs out of scope, rate limits, no destructive testing on prod, and when to STOP and ask the operator; load at the start of and throughout every engagement.
---

# Program Scope Discipline

Scope is the contract. Testing outside it is unauthorized access, not bug bounty — it burns the program, the operator, and you. This skill is short and firm on purpose: **when in doubt, stop and ask.**

## The core rule
Every request you send must target an asset that is **explicitly in scope** in the loaded engagement, tested within the **rules of engagement (ROE)**. If you cannot confirm both, do not send it.

## Read the program brief first (every time)
Before any recon or testing, extract and pin:
- **In-scope assets:** apex domains, wildcards, specific hosts, IP/CIDR ranges, mobile apps, APIs.
- **Out-of-scope assets:** explicit exclusions (they override wildcards), third-party/shared infrastructure, specific subdomains.
- **In-scope vulnerability types** and **excluded/known issues** (often: missing headers, self-XSS, rate limiting, CSV injection, etc.).
- **ROE:** allowed test accounts, testing windows, rate limits/throughput caps, required identifying header (e.g. `X-Bug-Bounty: <handle>`), PII handling rules, whether automated scanning is permitted.
- **Safe-harbor / legal terms** and disclosure policy.

Record this as `scope.md` and build `scope_domains.txt` / `scope_cidrs.txt` / `out_of_scope.txt` so tools filter automatically.

## In scope vs out of scope — quick decisions
- Wildcard `*.target.example.com` includes discovered subdomains **except** any listed as excluded.
- A subdomain resolving to third-party SaaS (S3, Zendesk, Heroku, GitHub Pages) → usually **out of scope** even if it belongs to the brand; do not test unless the brief says owned infra is in scope.
- Acquisitions/sister brands are **out of scope** unless explicitly listed.
- Found a juicy asset not in scope? Note it, do **not** test it. If it seems clearly theirs, ask the operator whether to request a scope expansion.

## Hard prohibitions (never, regardless of "it would prove impact")
- No **DoS / stress / load / volumetric** testing. No resource-exhaustion (recursive GraphQL, zip bombs, connection floods).
- No **destructive actions** on production data: no delete/overwrite/mass-modify of records that aren't yours, no corrupting other users' state.
- No **data exfiltration** beyond the minimum proof (one record / one callback / version string).
- No **unauthorized remote exploitation** beyond confirming the vulnerability — no persistence, no lateral movement, no pivoting into internal infra past the proof.
- No **social engineering, phishing, or physical** testing unless explicitly authorized.
- No testing against **real users' accounts** — use your own test accounts A/B.
- No **automated scanning** if the brief forbids it; otherwise throttle hard.

## Rate limits & good-neighbor testing
- Honor stated request/second caps. Absent a stated cap, stay gentle (e.g. `ffuf -rate 50`, low thread counts); back off on 429/5xx.
- Send the program's required identifying header on all traffic so blue teams can attribute you.
- Test during allowed windows only. Never let a scan run unattended against fragile hosts.

## STOP and ask the operator when:
- An asset's scope status is **ambiguous** (ownership unclear, third-party, unlisted subdomain).
- Confirming impact would require a **destructive, DoS, or data-exfil** action.
- You've reached **RCE / internal access / cloud creds** and further steps would pivot deeper.
- You discover **PII / secrets / other users' data** — capture minimal proof, then stop and ask how to handle.
- The finding might affect **production stability or real customers**.
- Anything in the ROE is unclear or seems to conflict with the task you were given.

Default posture: it is always correct to pause and confirm rather than risk an out-of-scope or destructive action.

## Pre-flight checklist (run before each testing session)
- [ ] Loaded the current engagement's scope + ROE
- [ ] Target host confirmed against `scope_domains.txt` / `scope_cidrs.txt`
- [ ] Not on the exclusion list; not third-party infra
- [ ] Rate limits and identifying header configured
- [ ] Using authorized test accounts, not real users
- [ ] Planned actions are non-destructive and within ROE

If any box is unchecked: do not proceed — resolve it or ask the operator.
