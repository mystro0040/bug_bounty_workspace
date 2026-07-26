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

---

# Voice — writing it so it reads like the operator wrote it

The structure above is sound and stays. This section is about how the prose sounds, and one rule
in it is not stylistic at all.

## 1. Never claim a human did what a tool did

**This is a truthfulness rule, not a preference.** A report saying *"the tester manually enumerated
the subdomains"* when `subfinder` produced the list is a false statement in a document the operator
signs their name to. On a program that discounts or refuses scanner-derived findings, it is a false
statement about the exact thing the program cares about.

Equally, do not write *"I ran…"* in a report the operator submits — the operator did not run it,
and a report in the first person makes a claim about who was at the keyboard.

The fix is to make the actor the tool or the observation, which is both honest and reads better:

| Don't write | Write |
|---|---|
| "The tester manually enumerated subdomains" | "Passive certificate-transparency enumeration returned 640 candidate names" |
| "I confirmed the endpoint returns 403" | "The endpoint returns HTTP 403 with a 3,108-byte WordPress `wp_die()` page" |
| "We scanned the host" | "An identified HTTP probe (one request per host, 5 req/s) returned…" |
| "Manual testing revealed…" | "`globalConfig.js` sets `window.domainList` to 28 suffixes" |

Naming the tool is not an admission of weakness — it is provenance, and a triager who can see
exactly how a result was produced trusts it more. What loses trust is a claim of manual work that
the evidence contradicts.

**Where a human genuinely did the work, say so plainly.** If the operator reproduced a PoC by hand
in a browser, "reproduced manually in Firefox 141 against a freshly-created test account" is true,
valuable, and exactly what a program asking for hand-validated findings wants to read.

## 2. Timestamps

Default: **no per-step timestamps.** They pad the report and a triager does not care what minute a
DNS lookup happened.

Include a timestamp when it is load-bearing:

- **A critical or time-sensitive finding** — a dangling domain, an exposed credential, anything
  where "as of when?" changes what the reader should do.
- **Anything that could have changed since** — re-verification of a transient state. "Re-verified
  still live 2026-07-26T05:05Z" tells the triager the window is open now.
- **Race conditions and timing oracles**, where the timing *is* the finding.
- **Rate-limit compliance**, when you need to show the pace was honoured.

Engagement-level dates always: when testing started and finished.

## 3. House style

Drawn from the operator's own reports (`engagement-lab-repo/*/reports/completed/`). These are the
habits worth carrying into bug bounty write-ups:

- **Lead with a verdict, in bold, as a complete sentence.** *"The target host was fully
  compromised."* — not "Several issues were identified." The reader should know the outcome before
  the second paragraph.
- **Say what did NOT work.** The pentest reports carry a *Security Strengths* section listing
  controls that held. In a bug bounty report the equivalent is a short "What was ruled out" — it
  proves the finding is not a guess, and it is the single fastest way to be taken seriously by a
  triager who reads a hundred speculative reports a week.
- **Explain why it matters beyond itself.** *"This finding is significant beyond the credential
  exposure itself:"* — then the second-order consequence. Impact sections that stop at the
  immediate effect read as incomplete.
- **Concrete artifacts, always.** Exact registry paths, byte counts, CVE numbers, header values,
  the literal string. Not "a configuration file" but the path.
- **Plain declarative sentences.** No hedging stacks ("it may potentially be possible that"), no
  hype ("critical!!"), no filler transitions.
- **Complete sentences over fragments.** Terse shorthand and arrow-chains (`A → B → fails`) are
  fine in working notes; a report is read once, cold, by someone with no context.

## 4. What to avoid because it reads as machine-written

- Three-item lists where two items would do, purely for rhythm.
- Section headers on a report short enough not to need them.
- Restating the finding at the top, middle, and end.
- "It's worth noting that", "It is important to understand", "In today's landscape".
- Equal weight given to every observation. Judgement means saying which parts matter.
- Perfectly parallel bullet structure. Real writing varies sentence length.

**Do not run the output through a "humanizer" tool.** It rewrites for texture at the cost of
precision, and precision is the whole product here — a triager reproducing from a reworded HTTP
request gets a different result. If a draft reads as machine-written, the fix is cutting it and
sharpening the verdict, not laundering the prose.

## 5. Two worked structures

### A. The standard finding — everything hangs off the verdict

```markdown
# [Medium] Dangling WordPress.com domain connection on site.example.com

**`site.example.com` routes to WordPress.com, which does not recognise it.** The hostname is an
in-scope asset and its DNS is under the program's control; the platform it points at has no site
bound to it. Anyone able to claim the hostname on WordPress.com serves arbitrary content on it.

## Evidence
`GET https://site.example.com/` returns HTTP 403, 3,108 bytes, from a WordPress.com origin:
- `server-timing: a8c-cdn, dc;desc=dfw` (a8c = Automattic)
- title: `Error: Active domain connection for this domain not found`
Re-verified 2026-07-26T05:05Z — still in this state four days after first observation.

## What was ruled out
- Not a takeover yet: no claim was attempted. This reports the dangling state, not possession.
- Not a stale record: the hostname resolves and the CDN answers; it is live, not abandoned DNS.
- No `_wpcom` verification TXT exists, so modern WP.com verification may block a claim. That is
  the open question, stated rather than assumed away.

## Impact
Phishing under the program's own domain, and cookies scoped to `*.example.com`.

## Remediation
Remove the DNS record, or bind the hostname to a controlled WordPress.com site.
```

Note what that does: verdict first, evidence second, **limits third**. The "what was ruled out"
section is what separates a report a triager trusts from one they have to interrogate.

### B. The negative result — worth writing, and rarely written

Programs remember researchers who tell them what is *clean*, and it is the honest output of most
sessions. It also protects the operator: a documented negative is not a finding withheld.

```markdown
# Coverage note — authentication surface, api.example.com

**No authorization flaw was found on the endpoints tested.** Recorded so the boundary of the
testing is legible, not to claim the surface is exhaustively clean.

## Exercised
| Class | Endpoints | Payloads / variants | Result |
|---|---|---|---|
| IDOR / BOLA | 14 | sequential + UUID substitution across 2 accounts | 403 on all |
| Mass assignment | 9 | role/owner/tenant injected into POST bodies | ignored, not reflected |

## Not exercised, and why
- Admin role endpoints — no admin account available (blocked on test accounts).
- Password reset flow — state-changing on a live account; requires operator approval.
```

The second table is the point. "Untested" and "clean" are different words and a report that
conflates them is the same failure as a finding whose numbers were computed over the wrong set.

## 6. On sourcing examples

Public HackerOne disclosed reports would be a good corpus and are deliberately **not** consulted
here: this workspace does not browse the open web (§2F-WEB), and that boundary is worth more than
the examples. If the operator wants a specific disclosed report used as a model, they can save it
into the engagement's folder and it becomes ordinary input.
