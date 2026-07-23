# Platform Profile — Intigriti

Standing Intigriti defaults the agent loads at engagement start. The **program's own policy always
wins when stricter**; this file fills in the platform baseline and the shorthand Intigriti programs
assume. (Vault note: captured scope data is filed under `simple_vault/data/bugbounty/intigrity/…`
— the folder uses the operator's `intigrity` spelling; the platform is **Intigriti**.)

Operator handle on Intigriti: **`mystro00040`** (confirm before use). Researcher identity on this
platform is your Intigriti **username** and/or your **`<username>@intigriti.me`** alias email.

Authoritative sources (seen in program policies — verify current text at these URLs):
- Community Code of Conduct: https://go.intigriti.com/coc
- Terms & Conditions: https://go.intigriti.com/tac
- Contextual CVSS standard: https://go.intigriti.com/cvss
- Triage standards: https://go.intigriti.com/triage-standards
- Platform: https://www.intigriti.com/

---

## ⛔ PRE-FLIGHT GATE — resolve ALL of these from the program's policy BEFORE any target contact
Read the specific program's **"Rules of engagement"** + **"Out of scope"** + its `changes` file and
answer each. Any ❌ you can't satisfy → STOP and flag the operator; never proceed on assumptions.

1. **Is automated tooling / scanning PERMITTED — and to what degree?** ⚠️ **Make-or-break gate.**
   Intigriti programs state this explicitly in *Rules of engagement → Automated tooling*. Two very
   different cases seen on this platform:
   - **A stated rate cap** (e.g. *"max. 5 requests/sec"*) — automation allowed, but you MUST throttle
     every scanner/enumerator to that cap or gentler. Honor it as a hard ceiling.
   - **Scanners effectively FORBIDDEN** — some programs (e.g. **DPG Media / Algemeen Dagblad**) say
     *"Please do NOT use automatic scanners… we cannot accept any submissions found by using automatic
     scanners."* On those programs: **manual-only mode** — hand-crafted requests, no `ffuf`/`nuclei`/
     `feroxbuster`/`sqlmap`/`katana` mass runs. A finding from a scanner will be **rejected** and can
     cause high server load / IP blocks. When in doubt, treat as manual-only and ask the operator.
2. **`@intigriti.me` identification — REQUIRED on Intigriti.** You must clearly identify as a
   researcher using your Intigriti username and/or `<username>@intigriti.me` email. **Bounty can be
   denied if you don't.** Use the intigriti.me alias for any signup/email the test needs.
3. **Attribution request header — PROGRAM-SPECIFIC (read it per program).** Intigriti programs each
   specify their own header under *Rules of engagement → Request header*. Seen so far:
   - DPG Media / Algemeen Dagblad → `X-Intigriti-Username: <username>`
   - Exact → `X-Bug-Bounty: Intigriti-<username>`
   Put the program's EXACT header on every request. Do not assume the framework default.
4. **Tiers (Tier 1–5) = asset priority, not scope-out.** Intigriti ranks in-scope assets by tier
   (Tier 1 highest value → Tier 5 lowest). All listed tiers are in scope unless marked out; use tier
   to prioritize effort (hunt Tier 1–2 first). Bounty scales with tier + contextual CVSS.
5. **Exact in-scope assets** — test ONLY what the *Domains/Assets* list names (respect wildcard vs
   host vs path, and any per-asset exclusions). Everything else is out of scope.
6. **Rate limits** — honor the stated *Automated tooling* cap (commonly 5 req/s here); default gentle
   regardless. Aggregate across all your tools against one host.
7. **Disclosure — STRICT on Intigriti.** No discussing or disclosing vulnerability info (incl. report
   titles, endpoints, company name, bounty amounts, **PoCs on YouTube/Vimeo**) without **prior written
   consent from BOTH Intigriti and the company.** Private-program details are confidential. If you
   record a video PoC, set it to **private**.

---

## Contextual CVSS + triage
Intigriti scores with its **contextual CVSS standard** (go.intigriti.com/cvss) and **triage standards**
(go.intigriti.com/triage-standards) — impact in the program's real context, not raw CVSS. Write reports
with a clear **attack scenario** ("how exactly does this affect us?") and to-the-point reproduction
steps, in English. **Quality over quantity** is explicitly rewarded; low-value/duplicate spam hurts you.

## Common out-of-scope (platform-typical — the program's own list still governs)
Programs here commonly exclude: self-XSS, missing cookie flags / security headers, CSRF with no/low
impact, CORS on non-sensitive endpoints, rate-limit issues (or their absence), best-practice violations
(password policy, autocomplete), reverse tabnabbing, clickjacking without proven impact, verbose
errors/version disclosure without sensitive data, pre-auth account takeover / OAuth squatting. Don't
chase or report these without a concrete high-impact chain.

## Safe harbor
Intigriti programs generally include a **safe-harbour clause** ("We respect the safe harbour clause you
can find below") — good-faith research conducted **inside the program's scope + rules of engagement** is
authorized and protected; step outside scope/ROE and you lose it. Confirm each program's clause is
present (most are) and flag the operator if a program lacks one.

## Cautions specific to Intigriti programs
- **Be wary on surfaces that touch real users** (e.g. job listings, contact/publish forms) or need
  manual back-end cleanup — test conservatively, benign markers only, never spam real users.
- **Shared-codebase duplicates:** media programs like DPG share code across brands (AD, De Morgen,
  Volkskrant, Parool, Humo, Trouw, Libelle) — an issue found on one may be a duplicate of another.

---

## Quick per-program checklist (agent fills this at engagement start)
```
platform: Intigriti
program: <name>
automation_permitted: <YES @ N req/s  |  NO — manual-only>   # ← the make-or-break gate
scope_type: <production / non-production / mixed>
in_scope_assets: <exact list, with tiers>
intigriti_me_identity: <username / username@intigriti.me>     # required
required_request_header: <program-specific, e.g. X-Intigriti-Username: <user>>
rate_limit: <stated cap, e.g. 5 req/s, or gentle default>
disclosure: NO without written consent from Intigriti + company
notable_exclusions: <program-specific + platform-typical>
```
