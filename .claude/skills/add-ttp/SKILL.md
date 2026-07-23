---
name: add-ttp
description: Dynamic discovery-loop committer. After the operator has reviewed and explicitly approved a specific framework-derived, scope-adapted TTP mid-engagement, this command appends it into the active engagement's approved_TTPs.yaml and recompiles .scope_lock/enforcement.json so the new boundary goes live immediately. Operator-triggered only; never runs autonomously.
disable-model-invocation: true
user-invocable: true
argument-hint: [engagement_name] [technique_ref]
arguments: [engagement, technique]
---

# /add-ttp — append an approved TTP to a live engagement (no reboot)

This is the **committer** for the dynamic discovery loop (global CLAUDE.md §2B). It runs ONLY
after you (the agent) have already: (a) halted on a discovered gap, (b) extracted the relevant
methodology from the read-only `FRAMEWORK_SOURCE` and adapted it to the current scope, and
(c) presented the exact proposed TTP block to the operator, who has **explicitly approved this
specific addition**. If any of that hasn't happened, STOP and run the §2B loop first.

`$engagement` = engagement folder. `$technique` = short ref/id of the technique being added.

## Step 0 — Preconditions (fail closed)
- Verify `.claude/state/active_engagement` names `$engagement` and
  `engagements/$engagement/approved_TTPs.yaml` exists with `approval.status: APPROVED`. If not,
  STOP — you can only extend an already-approved, active engagement.
- Confirm the operator's approval refers to **this** specific TTP block (restate it in one line).
  If approval is unclear, STOP and ask. Never self-approve.

## Step 1 — Tier 2 / locked guard
- If the source framework task is `policy.locked: true` or `policy.bounty_safe: false`, it is a
  protected TTP: it is **never** added automatically. Refuse unless the operator gives an
  **extra, explicit confirmation** naming the locked technique. Even then, flag it clearly.

## Step 2 — Asset-boundary guard
- The adapted commands must target only assets already inside the engagement's approved `assets`
  boundaries. If the technique requires a **new** in-scope asset (host/IP/range) that isn't in
  the current profile, that is a **scope change** — do NOT quietly widen it here. Tell the
  operator to add it to the scope file and run `/generate-scope <engagement> --update`, or get
  their explicit approval to add that specific asset as part of this step.

## Step 3 — Append to approved_TTPs.yaml
Add a new object under `approved_ttps:` mirroring the framework schema, marking its origin:
```yaml
  - id: <framework-task-id-or-derived>
    technique: <name>
    phase: <phase>
    intent: <what it's for, why it's in scope/compliant>
    poc_only: true
    binaries: [ <binary>, ... ]
    commands:
      - '<exact authorized command, scoped to in-boundary targets>'
    source: discovery-loop
    added_by: <operator>            # who approved
    added_note: <the finding/gap this resolves>
```

## Step 4 — Recompile enforcement.json (live boundary update)
- Read `engagements/$engagement/.scope_lock/enforcement.json`.
- Add the new TTP's `binaries` to `allowed_binaries` (dedup). Do **not** change `assets` unless
  the operator explicitly approved a new in-scope asset in Step 2 (then add it to the correct
  `assets` list). Leave `denied_patterns` intact.
- Write the updated `enforcement.json`. Because the PreToolUse hook reads this file fresh on every
  command, the new boundary is **live immediately — no restart needed**.

## Step 4b — Self-verify before going live (machine check)
After writing, confirm — if any fails, fix before reporting: `enforcement.json` still parses as
valid JSON; `allowed_binaries` now contains the new TTP's binaries and still equals the deduped
union across ALL approved TTPs; the new command's target host/IP is inside `assets`; the new
command carries its rate-limit flag and the `X-Bug-Bounty-Handle` header and matches no
`denied_patterns` entry.

## Step 5 — Confirm
Tell the operator exactly what was added: the technique, the new allowed binary(ies), any asset
change, and that the hook boundary is now active. Keep `approved_TTPs.yaml` and
`enforcement.json` in lockstep. If anything is uncertain, STOP rather than widen the boundary.
