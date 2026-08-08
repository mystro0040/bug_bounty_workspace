---
name: management-protocol
description: The protocol to follow when you are doing MANAGEMENT-type work — orchestrating sub-agents, reviewing scope or findings, framework maintenance, repo/propagation, and session bookkeeping. Load it when the current task is coordination/review rather than hands-on testing. It is guidance for a task, not an identity; the same session loads testing-protocol when it switches to hunting.
---

# Management-task protocol

This is a **situational guideline, not an identity.** You are not "a manager." When the task in
front of you is management-type work, follow this. When you switch to hunting, load
`testing-protocol` instead. One aware session, two protocols, whichever fits the task.

The invariants in `global/CLAUDE.md` — the hard floor (§3), the scope wall (§2A), the safety-flag
STOP (§2H), the always-halt cases (§2B), the usage-policy floor (§2I) — bind at full strength here
and are NOT restated in this file. This skill is the *how-to* for coordinating work; the config is
the *law*. Nothing here can loosen it.

## When this is your protocol

Orchestration and delegation · reviewing generated scope or a draft finding · framework-maintenance
(Tier 1) · repo commits and propagation · session bookkeeping (`_OPS/HANDOFF.md`, `ACTIONS.md`,
session logs, `engagements/_INDEX/`) · deciding what to hunt next and handing it off.

## The Omni-Manager posture

You default to orchestration, review, and maintenance, and you keep your own context clean so you
can hold the whole picture. You are **fully authorized to test targets directly when the operator
tells you to** — the scope wall governs the command, not your role, so there was never a code-level
bar on it. When you do pick up hunting yourself, load `testing-protocol` and follow it; don't run
noisy tools straight from the manager context if a sub-agent can do it and report up.

## Delegating to native sub-agents

You may spawn native sub-agents (via the Agent tool) to do the heavy, noisy lifting so your context
stays clean. **Cap: 3 concurrent.** The cap is a context-hygiene guard, not a throughput dial —
network concurrency is still governed by the per-host rate budget (§2F), so several testing
sub-agents against one host largely serialize anyway.

**Proven property (2026-08-07):** a sub-agent's Bash calls pass through the same PreToolUse hooks as
the main session — `enforce_scope.py` (scope wall) and `ram_guard.py` fire on them. Delegation does
not escape the wall. It inherits the session's `$AO_ENGAGEMENT` pin, so a sub-agent is scoped to the
same engagement automatically.

The reporting contract — **write down, report up:**

1. **The sub-agent writes full detail to the engagement files AS IT GOES** — `_COVERAGE.md`,
   `NOTES.md`, `findings/`, `BREAKTHROUGH_LEDGER.md`. The durable ledger is the source of truth.
2. **It reports UP to you only the synthesized signal** — errors that need a decision, an operator
   ask, or a confirmed/again finding — never a raw dump. Your context holds the conclusion, the
   files hold the evidence. A summary is a pointer to the record, never a replacement for it.
3. **The learning loop is the existing one.** A technique, a control that killed a false positive, a
   dead-end fingerprint → the sub-agent appends it to `BREAKTHROUGH_LEDGER.md`; promotion runs
   through `ttp_manager.py promote` and the `learning-loop` skill. Do not build a parallel loop.

Two operational duties delegation adds, both yours:

- **Process hygiene (§2F-STOP).** A sub-agent that spawns `ffuf`/`dnsx`/`nuclei` can orphan those
  processes when it ends. Track the PIDs it launched and clean them by PID — never `pkill` by name
  while another engagement may be running.
- **Rate accounting (§2F-NET).** Any network tool a sub-agent dispatches must `declare` to
  `rate_budget.py`, or the ISP cap divides by nothing. Sub-agent traffic ADDS to the same budget.

## The independent-review gates — do NOT self-review these two

The value the old two-session split protected was that scope and findings were reviewed by someone
*outside* the work. Keep that at exactly two gates, even as one aware session:

- **Scope approval.** Generated scope (`/generate-scope`) is reviewed before it goes live. A fresh
  sub-agent with clean context, or the operator, checks it — not the same reasoning that produced
  it. Scope still never self-approves; the operator is the final gate.
- **Finding validation.** Before a finding's status is raised past `draft`, a second pass (fresh
  sub-agent or operator) checks the control and the impact. This is the §1C control-gate with a
  second reader, which is exactly where four wrong verdicts slipped through once.

Everywhere else, one aware session is fine.

## Coordinating separate terminals (when you run them)

Native sub-agents report up in-process. If instead you run separate terminals (`$AO_ENGAGEMENT`
per terminal, §2F-PARALLEL), they coordinate **only through the engagement files** — `_STATUS.md`,
`_NEEDS-REVIEW/`, `_CONTROL.md`. Do not build or revive a messaging layer; the `.orchestrator/`
blackboard was retired and must not come back. Shared cross-engagement files (`_INDEX/`,
`_ACCOUNTS/`) are append-only and re-read before writing.

## Framework maintenance & propagation

- **Tier 1 maintenance is operator-triggered only.** You enter it when the operator says so, and
  only then does the framework read-only lock lift for the curation task. Ledger promotion into the
  master library happens here, git-versioned.
- **"Propagate" is never self-executing.** Confirm scope first (repos, or bucket staging + log?).
  The default from a non-home machine is bucket staging + `_framework-propagation/CHANGELOG.md`
  only; repos are touched only on an explicit "yes, update the repos," and only when
  `~/.config/offsec/machine_role` reads `home`. See the workspace root config's propagation section.

## Session bookkeeping

Start a session by reading `_OPS/HANDOFF.md`. Engagement facts go to the engagement as they happen.
Close with a session log, resolved `ACTIONS.md` rows, an overwritten `HANDOFF.md`, and
`python3 _OPS/check_ops.py`. The `wrap-up` skill does this end to end.

## Self-check before you hand work down or out

- The sub-agent's task names the engagement, the scope boundary, and which files to write to.
- You told it to write-down/report-up, not to dump.
- You have a way to reap its processes (PIDs), and its tools declare to the rate budget.
- Anything that widens scope or is forbidden/Tier-2 is NOT in the delegated task — those halt for
  the operator, always.
