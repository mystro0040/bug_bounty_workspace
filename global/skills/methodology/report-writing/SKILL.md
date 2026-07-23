---
name: report-writing
description: Write a platform-ready bug bounty report (HackerOne/Bugcrowd style) with title, summary, reproduction steps, impact, remediation, and severity; use once a finding is validated and you are ready to submit.
---

# Report Writing

A report gets paid when the triager can **reproduce it in minutes** and **immediately sees the impact**. Clarity and reproducibility beat volume every time.

## Principles
- Write for a busy triager: skimmable, exact, no filler.
- Every reproduction step must be copy-pasteable and complete (URLs, headers, bodies, accounts).
- Lead with impact; make severity self-evident and justified.
- Redact real PII in evidence; show enough to prove, not to expose.
- One vulnerability per report unless the program wants a chain documented together.

## Title formula
`[Severity] <Vuln type> in <component/endpoint> leading to <concrete impact>`
- Good: `[High] IDOR in /api/v1/invoices/{id} allows any user to read other tenants' invoices`
- Bad: `Security issue found`, `IDOR vulnerability`

## Before submitting — checklist
- [ ] Correct program + asset is **in scope**
- [ ] Not a duplicate (search disclosed reports / your notes)
- [ ] Steps reproduce from a clean session
- [ ] Impact is concrete and matches CVSS vector
- [ ] Evidence attached (annotated screenshots, raw HTTP, callback logs)
- [ ] PII redacted; PoC is non-destructive
- [ ] Remediation guidance included

## Severity
State CVSS 3.1/4.0 vector + score and the qualitative rating. Match the program's own rating table if provided. Don't inflate — triagers downgrade obvious padding.

---

## Reusable template

```markdown
# [Severity] <Vuln type> in <endpoint/component> leading to <impact>

## Summary
One or two sentences: what the bug is, where it lives, and what an
attacker achieves. A triager should grasp the whole issue from this alone.

## Severity
- Rating: <Critical|High|Medium|Low>
- CVSS 3.1: <score> — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`

## Affected asset / scope
- Target: https://target.example.com
- Endpoint(s): `POST /api/v1/...`
- In-scope per program: yes

## Prerequisites
- Accounts/roles needed (e.g. two standard user accounts: Attacker, Victim)
- Any preconditions or configuration

## Steps to Reproduce
1. Log in as Attacker (account A) and capture the request to `...`.
2. Note Victim (account B) object ID: `<id>`.
3. Replay the request substituting B's ID:
   ```http
   GET /api/v1/invoices/<B_id> HTTP/1.1
   Host: target.example.com
   Authorization: Bearer <A_token>
   ```
4. Observe the response returns Victim B's data:
   ```http
   HTTP/1.1 200 OK
   { "invoice_id": "<B_id>", "owner": "victim@...", ... }   # redacted
   ```

## Proof of Concept
- Attach: annotated screenshot(s), raw request/response, OOB callback log.
- PoC is non-destructive: only a single unauthorized read was performed.

## Impact
Concrete consequences: who/what is affected, scale, trust boundary crossed,
data/money/accounts at risk, and any chaining to greater impact.

## Remediation
Specific, actionable fix: enforce object-level authorization checking that
the authenticated user owns the requested resource on every request; use
unpredictable identifiers; add server-side access-control tests.

## References
- OWASP API1:2023 Broken Object Level Authorization
- CWE-639 Authorization Bypass Through User-Controlled Key
```

---

## Section guidance
- **Summary:** the single most important paragraph. Type + location + impact in plain language.
- **Steps:** numbered, minimal, deterministic. Include exact requests. Assume the triager has nothing but your report.
- **PoC evidence:** annotate screenshots (arrows/boxes). Include raw HTTP and callback timestamps. Prefer text + image over video, but a short video helps for multi-step chains.
- **Impact:** answer "so what?" — quantify (e.g. "any of N users", "full account takeover", "read of arbitrary tenant data"). Spell out the chain if the bug's severity depends on it.
- **Remediation:** show you understand the root cause; cite the correct control, not just "sanitize input".
- **References:** OWASP Top 10 / API Top 10, CWE ID, relevant docs — signals rigor and helps triage.

## Tone & handling
- Professional and factual. No hype, no threats, no demands about bounty amount.
- If the program asks a follow-up, respond precisely and re-verify if needed.
- Never publicly disclose before the program authorizes it.

## Common report-quality failures to avoid
- Vague impact ("this is dangerous") with no concrete attacker scenario.
- Steps missing an account/precondition, so it can't be reproduced.
- Scanner output pasted as-is with no manual confirmation.
- Reporting out-of-scope assets or informational noise as if payable.
