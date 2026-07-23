# Platform Profile — HackerOne

Standing HackerOne defaults the agent loads at engagement start. The **program's own policy always
wins when stricter**; this file fills in the platform baseline and the shorthand programs assume.

Authoritative sources:
- HackerOne Code of Conduct: https://www.hackerone.com/policies/code-of-conduct
- HackerOne Disclosure Guidelines: https://hackerone.com/disclosure-guidelines
- HackerOne Core Ineligible Findings: https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings

---

## ⛔ PRE-FLIGHT GATE — resolve ALL of these from the program's policy BEFORE any target contact

The agent must read the specific program's policy/scope and answer each. Any ❌ that can't be
satisfied → STOP and flag the operator; do not proceed on assumptions.

1. **Is automated security testing / scanning PERMITTED?**
   ⚠️ **This is the make-or-break gate.** Many mature programs (e.g. **Agoda Public**) list
   *"Performing automated security testing or scanning"* as a **Prohibited Action** and reject
   automated scanner output in reports. If automation is **prohibited**:
   - Do **NOT** run `ffuf`, `feroxbuster`, `nuclei`, `sqlmap`, `httpx` mass probes, `katana`, or any
     fuzzer/scanner.
   - Switch to **manual-only mode**: hand-crafted single requests, human-paced, curl/proxy only.
   - If the engagement can't meaningfully proceed manually, tell the operator — don't improvise.
   Running scanners on a no-automation program risks bounty loss, disqualification, and **account
   ban / platform deactivation.**
2. **Production or non-production scope?** If the in-scope asset is a **live production** system
   (real users/data/money — e.g. a checkout/booking flow), treat blast radius as maximal: no
   state-changing actions, no real customer data, benign markers only. There is no "run a copy" here.
3. **Exact in-scope assets** — test ONLY assets explicitly listed as in-scope. Launch-phase programs
   often list a single asset; everything else is out of scope and will be closed (and may be a ban).
4. **Required identifier** — most H1 programs require a marker so testing is distinguishable from
   abuse. Common form: `User-Agent: hackerone-<your-username>`. Some also require a
   `@wearehackerone.com` email. **Use the program's exact required form** (it may differ from the
   lab default `X-Bug-Bounty-Handle`). Missing it can get your account deactivated on the target.
5. **Rate limits** — honor any stated limit; default gentle regardless.
6. **Excluded / risk-accepted findings** — see below + the program's own exclusions; don't waste a
   report (or testing) on these.
7. **Disclosure policy** — HackerOne default is coordinated/program-controlled. Many programs (e.g.
   Agoda) forbid any disclosure. Never disclose without explicit program permission.

---

## Core Ineligible Findings (platform-wide — expand "Core Ineligible Findings are out of scope")

When a program's overview says *"Core Ineligible Findings are out of scope"* (very common on H1),
it means **this list**. These are closed as invalid except with clear, demonstrated security impact.
The agent should **not chase or report** these without a concrete high-impact chain.

**Theoretical / unlikely-interaction:**
- Bugs only affecting EOL/unsupported browsers or OSes
- Broken link hijacking
- Tabnabbing
- Content spoofing / text injection
- Attacks requiring physical device access (unless explicitly in scope)
- Self-exploitation (self-XSS, self-DoS) unless it can attack a *different* account

**No demonstrated real-world impact:**
- Clickjacking on pages with no sensitive actions
- CSRF on forms with no sensitive actions (e.g. logout)
- Permissive CORS without demonstrated impact
- Software-version / banner disclosure; descriptive errors / stack traces / server errors
- CSV injection
- Open redirects (unless additional security impact is demonstrated)

**Optional hardening / missing best practice:**
- SSL/TLS configuration; lack of SSL pinning
- Lack of jailbreak detection in mobile apps
- Cookie flags (missing HttpOnly/Secure)
- Content-Security-Policy opinions
- Optional email security (SPF/DKIM/DMARC)
- Most rate-limiting issues

**Hazardous testing — NEVER attempt unless explicitly authorized (these also hit our hard floor):**
- Excessive traffic / DoS / DDoS
- Anything that may affect availability of systems
- Social engineering (phishing, support requests)
- Attacks noisy to users/admins (notification/form spam)
- Attacks against physical facilities

---

## Identifier & test-account conventions
- Self-provision your own test accounts; never touch real users' accounts/data.
- Put the required identifier where the program asks (usually `User-Agent`), and optionally in other
  benign parameters. Keep it on every request.
- Leaked-credential findings: report the **evidence of leakage only** — do NOT validate, log in with,
  or act on leaked credentials.

## Safe harbor
Activity consistent with a program's policy is authorized conduct under that program's safe-harbor
terms. Stay inside the policy and you stay protected — step outside scope/ROE and you don't.

---

## Quick per-program checklist (agent fills this at engagement start)
```
platform: HackerOne
program: <name>
automation_permitted: <YES / NO — from Prohibited Actions>   # if NO -> manual-only or stop
scope_type: <production / non-production / mixed>
in_scope_assets: <exact list>
required_identifier: <e.g. User-Agent: hackerone-<username>>
rate_limit: <stated limit or "gentle default">
disclosure: <allowed? usually NO>
notable_exclusions: <program-specific + Core Ineligible Findings>
```

## Attribution-header discipline (reward-critical on header-required programs)
Some programs require an attribution header on ALL traffic (e.g. `X-Bug-Bounty: HackerOne-<user>`), and a
MISSING header can be reward-impacting or forfeiting. When a program requires one:
1. Visit the program's pre-testing/attribution URL in the capture browser first (often sets it for ~1 week).
2. Inject the header on EVERY curl/replay request — and VERIFY it is present on a sample captured request
   before trusting a session (browser captures can silently omit it if the pre-testing URL wasn't visited).
