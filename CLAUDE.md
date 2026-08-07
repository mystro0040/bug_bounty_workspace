# Bug Bounty Workspace — root config loader

<!-- Claude Code auto-loads THIS file from the workspace root, then imports the full global
     configuration below. The authoritative agent config, hard rules, and scope-gating
     guardrails live in global/CLAUDE.md. -->

@global/CLAUDE.md

---

Operational reminder: on every session, follow the **Initialization protocol** and
**Phase 1 (Initialization check)** in the global config before doing anything else. If the
selected engagement has no populated `approved_TTPs.yaml`, you are locked down — tell the
operator to run `/generate-scope <engagement>` first.

---

## ⛔ START HERE EVERY SESSION — `_OPS/HANDOFF.md`

**The first file you read is `_OPS/HANDOFF.md`.** Always that exact path. Read `_OPS/README.md`
once to understand the layout; after that the handoff is enough.

This exists because session state and operator action items had no defined home, so every session
invented its own filenames — producing dozens of loose files under a dozen prefixes, none carrying
a state. Per-engagement state was never the problem; that layer works.

### Three kinds of writing, three homes. Nothing else.

| Kind | Home |
|---|---|
| What is true about ONE program | `engagements/<eng>/` — `_STATUS.md`, `_PLAN.md`, `_COVERAGE.md`, `NOTES.md`, `BREAKTHROUGH_LEDGER.md`, `_NEEDS-REVIEW/` |
| What happened in ONE sitting, across everything | `_OPS/sessions/YYYY-MM-DD-N.md` |
| Anything only the OPERATOR can do | `_OPS/ACTIONS.md` — one row, always with a state |

Plus exactly one pointer: **`_OPS/HANDOFF.md`**.

### The rules, and each one is there because it broke

1. **The handoff holds no content.** It is an index. Every fact has exactly one home and the
   handoff points at it. Once it restates an engagement's `_STATUS.md`, that fact exists twice, the
   copies drift, and the next agent has to work out which is true.
2. **`HANDOFF.md` never has a date in its name.** A dated handoff can be created again tomorrow
   beside today's. One path, overwritten; history lives in the session logs and in git.
3. **Every `ACTIONS.md` row carries a state** — `OPEN` / `BLOCKED` / `DONE` / `DROPPED` with a
   reason. An item nobody closed shows as open rather than lying around looking like litter.
4. **The desktop is for the OPERATOR, never for agents.** Runbooks, verification walkthroughs and
   approvals belong where they work — with a matching `ACTIONS.md` row. Agent handoffs, session
   state and coverage notes never go there. The test: if the reader is another agent, it goes in
   the workspace.

### What a session does

- **Start:** read `_OPS/HANDOFF.md`, then the `_PLAN.md` of whatever it names.
- **During:** engagement facts go to the engagement AS THEY HAPPEN.
- **End:** write `_OPS/sessions/<today>-N.md`, update the `ACTIONS.md` rows you resolved, overwrite
  `_OPS/HANDOFF.md`, then run `python3 _OPS/check_ops.py`.

`check_ops.py` is WARN-only and never blocks testing — an untidy record is a debt, not an unsafe
condition.
