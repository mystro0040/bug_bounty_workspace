# Operating modes — how this workspace runs

Simple model: **one hard floor that's always on, plus two modes controlled by one switch.**

## The hard floor (always on — cannot be turned off, any mode)
Enforced in code by the PreToolUse hook, for every engagement:
- **Only in-scope targets.** Anything off the approved assets is blocked.
- **Never** DoS/flooding, credential **brute-forcing**, social engineering, or destructive/system
  actions. These are hardcoded in the hook and can't be removed by editing any scope file.
- Everything stays **legal and authorized.**

## Two modes — one switch: `AUTONOMOUS_MODE` in `global/CLAUDE.md` §0

| Situation | Supervised (`false`) | Autonomous (`true`, default for now) |
|---|---|---|
| Running the **approved** techniques | runs them | runs them |
| Needs a **new in-scope, non-forbidden** technique | **stops & asks** you | **adds it, logs it, keeps going** |
| Wants a **new target / asset** | always **stops** | always **stops** |
| A **forbidden** technique (DoS/brute/social/destructive) | blocked + stops | blocked + stops |
| You walk away for hours | waits at the first gap | keeps testing on its own |

**Autonomous never means unbounded:** it can only add *in-scope, framework-derived, non-forbidden*
techniques, and it **logs every one**. New targets and forbidden techniques always wait for you.

## Where to look (all inside the engagement folder)
- **`_NEEDS-REVIEW/NN_*.md`** — numbered items, newest last. Things waiting for you, or (in
  autonomous) records of what it self-added, marked "self-added (FYI)". Open these in an editor.
- **`NOTES.md`** — the live run log.
- **`BREAKTHROUGH_LEDGER.md`** — every fix / bypass / new-technique discovery.

## How to switch modes
Flip the backticked value of `AUTONOMOUS_MODE` in `global/CLAUDE.md` §0 (`true`/`false`), then
restart the session so it reloads.

## Permission mode (a separate Claude Code setting)
To run **unattended without per-action prompts**, start the session with
`claude --permission-mode auto` (or press **Shift+Tab** to cycle to it — `plan` mode only plans, it
won't execute). Either way, the hook still enforces the hard floor + scope in every permission mode.
## Operating model — one aware session, task-based protocols, native sub-agents

You run as **one aware master session** (the "Omni-Manager") that defaults to orchestration, review,
and framework maintenance, and is **fully authorized to test targets directly when the operator says
so.** There is no "you are a tester" / "you are a manager" identity lock — the scope wall governs the
command, not the role. Instead the session loads the **protocol for the task in front of it**:

- **`management-protocol`** (skill) — orchestrating, reviewing scope/findings, maintenance,
  propagation, session bookkeeping. Load it for coordination-type work.
- **`testing-protocol`** (skill) — recon, enumeration, hunting, validation, PoC. Load it for
  hands-on work, whether the main session is testing or a sub-agent was handed a testing job.

The same session switches protocols as the task changes. Neither can loosen the hard floor above.

### Native sub-agents — heavy lifting delegated, context kept clean

The master session may spawn **native sub-agents (cap: 3 concurrent)** to do the noisy, heavy work
so its own context stays clean. The protections fire on them: a sub-agent's Bash calls go through the
same PreToolUse hooks (`enforce_scope.py`, `ram_guard.py`) as the main session, and inherit the
`$AO_ENGAGEMENT` scope pin — verified 2026-08-07. The contract is **write-down, report-up**: the
sub-agent writes full detail to the engagement files as it goes and reports up only the synthesized
signal (errors, decisions needed, findings). Delegation adds two duties on the manager — reaping the
sub-agent's processes by PID (§2F-STOP) and declaring their tools to the rate budget (§2F-NET). Full
mechanics live in `management-protocol`.

### Independent review is preserved at two gates

The value the old two-session split protected was that scope and findings were checked by someone
outside the work. Keep that at exactly two gates, even as one session: **scope approval** and
**finding validation** get a second reader — a fresh sub-agent with clean context, or the operator —
never pure self-review. Scope still never self-approves; the operator is the final authority.

### Separate terminals still work

Running two real terminals (`$AO_ENGAGEMENT` per terminal, §2F-PARALLEL) is still supported for
parallel engagements. They coordinate **only through the engagement files** — `_STATUS.md`,
`_NEEDS-REVIEW/` (every operator-ask, CLAUDE.md §2D), `_CONTROL.md` (next step, stale-safe). No
messaging layer: the `.orchestrator/` blackboard was retired and stays retired.
