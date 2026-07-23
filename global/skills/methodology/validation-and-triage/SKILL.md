---
name: validation-and-triage
description: Safely prove a finding with a minimal non-destructive PoC, rule out false positives, assess real-world impact, map to CVSS, and decide payable vs informational; use after a candidate bug is found and before writing a report.
---

# Validation & Triage

Between "I think I found something" and a submitted report sits this gate. Its job: confirm the bug is **real**, prove it **safely**, size its **impact**, and decide whether it's **worth reporting**.

## Rules
- Prove with the minimum: one record, one callback, one forged token — enough to be undeniable, nothing more.
- Never destroy, never bulk-extract, never pivot beyond the proof. If a full exploit would require destructive action, describe the chain instead of executing it.
- Stay in scope for every validation request.

## Step 1 — Reproduce deterministically
- Reproduce the issue **at least twice**, ideally from a clean session/state.
- Strip the request to the minimum needed to trigger it. Remove unrelated headers/params.
- Record exact request + response (raw HTTP), timestamps, account context (A vs B), and any preconditions.
- If it only works once or intermittently, identify why (caching, race, session state) before reporting.

## Step 2 — Kill false positives
Common false positives and how to disprove them:
- **"IDOR"** that returns your *own* data due to session, not the swapped ID → re-test fully logged out or as the other account.
- **Reflected value ≠ XSS** → confirm it executes in a browser (breaks out of context, not HTML-encoded), not just reflected.
- **SQLi time delay** from network jitter → repeat with `SLEEP(0)` vs `SLEEP(5)`, multiple trials.
- **SSRF** that resolves DNS via a scanner, not the target → confirm the callback source IP is the target's.
- **Open redirect** to a page that sanitizes → verify final landing origin.
- **Scanner output** (nuclei/sqlmap "found") is a lead, not proof — always hand-verify.
- Check it isn't **intended functionality**, a **known/duplicate** issue, or something requiring **unrealistic preconditions** (attacker already admin, victim runs arbitrary JS, MITM on TLS without cause).

## Step 3 — Minimal non-destructive PoC
- **Read access:** display one unauthorized record (redact PII in the report).
- **SSRF/RCE/deserialization/XXE (OOB):** a single DNS/HTTP beacon to your interactsh domain, or read `/etc/hostname`.
- **SSTI/RCE:** evaluate `{{7*7}}` or run `id` once — no destructive commands.
- **ATO:** take over an account **you own**.
- **SQLi:** extract DB version or one benign string, not table dumps.
- Prefer a benign marker (`alert(document.domain)`, unique callback token) over anything that touches other users.

## Step 4 — Assess real-world impact
Ask, concretely:
- What can an attacker actually do? Whose data/money/accounts, and how many?
- What are the preconditions and how realistic are they?
- Does it cross a tenant/trust boundary? Is auth required? Is user interaction required?
- Does it chain? A "medium" that yields ATO or internal access is high/critical — build the chain.

## Step 5 — Map to CVSS 3.1 / 4.0
Score honestly; inflated scores get downgraded and hurt credibility.
```
AV (Network/Adjacent/Local) | AC (Low/High) | PR (None/Low/High)
UI (None/Required) | Scope (Unchanged/Changed) | C/I/A (High/Low/None)
```
- Use CVSS Scope=Changed when the bug affects resources beyond the vulnerable component (e.g. SSRF reaching cloud metadata).
- Provide the vector string, not just the number.

Rough anchors: ATO/RCE/SQLi/full BOLA → Critical/High. SSRF to internal → High. Blind SSRF no impact / limited IDOR → Medium. Reflected self-XSS / info leak → Low/Info.

## Step 6 — Payable vs informational decision
**Report it when:** clear security impact, realistic attacker, crosses a trust boundary, in scope, not a known dupe. Payable classes: ATO, IDOR/BOLA, SSRF, SQLi, auth bypass, RCE, privilege escalation, impactful business logic, sensitive data exposure.

**Hold / don't report (informational noise):**
- Missing security headers, cookie flags, HSTS, CSP nits — alone.
- Verbose banners/version disclosure, stack traces without sensitive data.
- Self-XSS, clickjacking on non-sensitive pages, tabnabbing, no-impact CSRF.
- Best-practice recommendations, missing rate limit on non-sensitive endpoints.
- Anything out of scope or affecting only assets you don't own.
- Exception: include a noise item **only** when it materially chains into an impactful finding — and frame it as part of the chain.

## Handoff checklist
- [ ] Reproduced ≥2x, minimized request/response captured
- [ ] False positives ruled out; not a known dupe / intended behavior
- [ ] Non-destructive PoC captured (screens/HTTP/callback logs)
- [ ] Impact articulated + CVSS vector assigned
- [ ] In scope confirmed; decision = payable

Pass everything to **report-writing**.
