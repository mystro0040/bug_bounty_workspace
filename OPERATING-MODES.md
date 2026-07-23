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
## Two-session operating model (recommended for live engagements)

Run the framework as **two coordinated sessions**, not one:

- **Working session** — the engagement executor. Launched from the workspace/bucket root, it loads an
  engagement and operates strictly inside the scope wall, doing the hunting. Keep its context clean
  (scope, tools, findings). Tactical, in-engagement questions go here.
- **Management / auditor session** — an independent overseer, launched separately. It reviews the
  working session's generated scope and approval requests **from the files**, does framework/config
  maintenance and repo commits, and relays decisions. Because it sits **outside** the engagement wall,
  its review is an independent check, not self-review. Strategy / "is this scope safe?" questions go here.
- **You** are the bridge and the final authority — you approve scope, answer the asks, and decide.

**Why split them:** independent review catches what self-review misses; the worker stays focused and
context-clean; meta-work (config, commits, hardening) happens without disturbing the live run; and if
the working session crashes, the management session persists to help it recover.

**How they stay in sync — entirely through the engagement files, no screen-sharing needed:**
- The worker writes state to `_STATUS.md` and **every operator-ask to `_NEEDS-REVIEW/`** (CLAUDE.md
  §2D, gated by `OPERATOR_ASK_TO_FILE`) — so the auditor/operator can review from the files alone.
- The operator/auditor hands the worker its next step via `_CONTROL.md` (conditional, stale-safe).
- A watcher (a monitor, or the auditor session) reads those files and surfaces changes.

A single combined session is fine for quick or solo tasks; for a live engagement, prefer the split.
