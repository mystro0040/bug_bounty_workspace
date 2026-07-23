---
name: reporting
description: Write clear, high-value bug bounty reports — reproducible steps, CVSS-aligned severity, root-cause and business-impact framing, actionable remediation, and redacted evidence. Use when writing up any finding for submission to a program.
---

# Reporting Guidelines (bug-bounty-safe subset)

Distilled from the user's Pentest Execution Framework — the reporting subset of Phase 07, reframed for bug bounty submissions. Full-engagement deliverables (executive roadmaps, attestation letters, client debrief/closeout, infrastructure destruction) are out of scope here.

> Authorized, in-scope engagements only — verify the target is within the loaded engagement's scope/ROE before use. Runnable examples use placeholder targets, not real third parties.

## The report is the product
The program pays for a clear, reproducible write-up — not for how clever the exploit was. A poorly documented Critical loses its value (and its payout).

## Anatomy of a strong submission
1. **Title** — bug class + asset + impact in one line (e.g. "IDOR in /api/orders/{id} → any user's order data").
2. **Severity** — CVSS v3.1/v4.0 vector + score. Calibrate:
   - **Critical (9.0–10.0):** unauth RCE, full account/data takeover at scale.
   - **High (7.0–8.9):** high impact requiring auth or interaction (authenticated SQLi, stored XSS → ATO).
   - **Medium (4.0–6.9):** limited/conditional impact (reflected XSS, non-sensitive info disclosure).
   - **Low (0.1–3.9):** best-practice violations with no direct exploit path.
3. **Affected asset** — exact in-scope URL/endpoint/parameter.
4. **Steps to reproduce** — numbered, copy-pasteable. An engineer must recreate it without guessing. Include the raw request/response.
5. **Proof of concept** — minimal and non-destructive (see web-app-exploitation-poc). Screenshots/HTTP logs proving impact.
6. **Impact** — plain-English business risk (Likelihood × Impact). What can an attacker actually do?
7. **Root cause** — the underlying flaw, not just the symptom (e.g. "user-controlled object ID with no ownership check," not "the page is broken").
8. **Remediation** — the exact fix (e.g. "enforce server-side authorization on the object ID; use parameterized queries," not "fix the code").

## Quality bar before you submit
- **Reproducibility:** can someone copy/paste your steps and see it? If not, tighten them.
- **Redaction:** blur/redact real credentials, tokens, hashes, and any PII/PHI in screenshots and logs.
- **Tone:** objective and professional. Drop "obviously," "easily," "trivially."
- **Scope:** the asset is in scope and the PoC did no damage. Never submit findings on out-of-scope/third-party assets.

## De-prioritize (usually not payable alone)
Missing security headers, verbose `Server`/`X-Powered-By` banners, non-sensitive directory listings, self-XSS, and best-practice nits without a demonstrated attack path. Bundle as informational at most.

## Common finding → business-risk phrasing
Insufficient authentication controls (missing MFA), weak password policy, insufficient patching, default credentials, insufficient encryption (HTTP/legacy TLS), information disclosure (backups, verbose errors), username enumeration, broken access control. Translate the technical bug into one of these so the program's triage team grasps the risk instantly.
