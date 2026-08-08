---
name: testing-protocol
description: The protocol to follow when you are doing TESTING-type work — recon, enumeration, vuln hunting, validation, PoC, and getting a finding ready. Load it when the current task is hands-on hunting, whether you are the main session testing directly or a sub-agent handed a testing job. It is guidance for a task, not an identity; the same session loads management-protocol when it switches to coordination.
---

# Testing-task protocol

A **situational guideline, not an identity.** When the task is hands-on hunting, follow this —
whether you are the aware main session testing on the operator's command, or a sub-agent handed a
testing job. When you switch back to coordinating, load `management-protocol`.

The invariants in `global/CLAUDE.md` bind at full strength and are not restated here: in-scope
assets only, no DoS / brute-force / social-eng / destructive actions (§3), the scope wall (§2A),
WAF/edge and safety-flag evasion forbidden (§2G/§2H), the usage-policy floor (§2I). This skill is
the *how-to* of hunting well inside those lines.

## Before the first request — resume, don't restart

1. Read the engagement's `changes` file (if any) — it overrides older scope (root config).
2. `python3 <FRAMEWORK_SOURCE repo>/utilities/engagement/plan.py next --engagement <eng>` — what
   is UNTESTED. Then read `_PLAN.md` (position, parked, closed-and-why) and `_COVERAGE.md`.
3. Confirm where tools run: if execution resolves to `remote`, every network tool runs ON the
   executor — you dispatch it, nothing routes automatically (§2F-NET).

The plan tells you what is untested, not what to do — that stays your judgement, and a better
in-scope idea than anything listed is taken first (§2B-AUGMENT).

## The methodology skills carry the depth

Load the class-specific playbook rather than working from memory:

- `recon-and-asset-discovery` · `web-vulnerability-hunting` · `api-and-auth-testing` ·
  `validation-and-triage` · `proxy-driven-testing` (methodology/)
- `web-content-discovery-and-triage` · `web-vulnerability-analysis` · `web-app-exploitation-poc`
  (ttp-derived/)

## Hunt like the bug is there (§1B, condensed)

- **Deep, not wide-and-shallow.** Fully enumerate — JS bundles, source maps, wayback, GraphQL
  introspection, param mining. A wildcard in scope means ACTIVE subdomain brute-force + permutation,
  not just passive/CT. Persist the resolved inventory to a durable recon folder, not `temp/`.
- **Attack the logic.** On hardened targets the payable bugs are authorization and business logic —
  IDOR/BOLA, tenant boundaries, workflow/state abuse, price/quantity manipulation, races. Spend most
  effort here.
- **Chain.** Low + low is often a payable chain. Hunt the chains.
- **Exhaust the payload space per class.** plain → URL-encoded → double/triple → unicode/overlong →
  mixed-case → comment/whitespace → nested/second-order → context breakouts. Defeating the *app's*
  input filter is in scope; evading the *infrastructure's* WAF block is not (§2G).
- **Version → CVE.** Fingerprint the stack, check known CVEs (`nuclei -tags cve`, `searchsploit`,
  `wpscan`), confirm safe ones with a minimal non-destructive PoC.

## Record as you go — the coverage ledger is the anti-duplication mechanism

- Test first, record after. `plan.py cover ... --state clean --note '<why>'`. A `clean` row must
  carry the reason; the tool refuses it without one. `blocked`/`walled`/`finding` likewise carry
  what would unblock / date+signal / the id.
- "Exhausted" is a number: `python3 _OPS/surface_report.py`. Never claim clean from memory.
- Write the per-class coverage matrix under `04_Vulnerability_Analysis/` before calling a surface
  clean. A class you did not exercise is **untested**, not clean.

## The two gates before a finding is real

- **Reporting gate (§1C).** Before drafting: what is the demonstrated impact, is a PoC required for
  this class and do you have one, is it excluded (program + platform core-ineligible list)?
  Informational-but-accepted is fine; ineligible is not.
- **Control gate (§1C, code-enforced).** Raising a finding past `draft` requires a control — the
  same test with a value that must NOT fire, and what it did. `findings_store` refuses `confirmed`/
  `reported` without one. Run the control BEFORE the write-up.

## When the target pushes back (§2G)

A `429`/`503`/CF-`1015`/HTML challenge = WAF wall: stop that host, one gentle re-confirm at most,
never evade, mark it `walled`, pivot to other in-scope work. A plain `401`/JSON-`403` = normal authz
= keep pushing. Multiple hosts blocking together or escalating on one = account-safety tripwire =
HALT all network testing and tell the operator.

## Keep progressing — don't stop to ask for permitted work

While in-scope permitted surface remains, keep testing without being asked. Finishing a thread is
the cue to start the next untested one in the same turn. The only things that stop you: a NEW target,
a forbidden/Tier-2/state-changing technique, a safety flag (§2H), or an explicit operator hold.
Reporting a bug or clearing a lead is not a stopping point.

## Clean stop (§2F-STOP)

Kill every background job you started, by PID. Close the executor SSH master
(`remote_data.py disconnect`). Verify with `opsec_check.py` ("nothing scanning here"). Then write
`_STATUS.md` with a resumable checkpoint. A pause is clean only when no orphaned jobs remain AND the
resume state is written.
