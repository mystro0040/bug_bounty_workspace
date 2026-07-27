# 01 — The program rate ceiling is not enforced on hand-written commands

**Status:** 🟡 OPEN — found 2026-07-27, not yet fixed
**Severity:** real gap, no violation occurred

## What was found

The operator asked why 24,000 subdomains appeared so quickly under a rate limiter. The benign
answer is that passive enumeration queries third-party aggregators in bulk and never touches the
target. Checking it properly surfaced something else.

**A hand-written command can exceed the program's stated rate ceiling and the wall allows it.**

Measured against an engagement lock, whose documented ceiling is **5 req/s**:

| Command | Verdict |
|---|---|
| `httpx … -rl 5` | ALLOWED |
| `httpx … -rl 50` | **ALLOWED** — 10× the program ceiling |
| `httpx … -rl 99` | **ALLOWED** — ~20× |
| `httpx … -rl 150` | denied (hard DoS floor) |
| `httpx … -rl 900` | denied (hard DoS floor) |

## Why it happens

The ceiling is enforced in `scope_compiler._clamp_rates()`, which rewrites rate flags **in the
compiled TTP command templates**. Run a command out of `approved_TTPs.yaml` and it is clamped.

Type your own and nothing checks it. `enforcement.json` does not carry the ceiling at all — the
hook has no value to compare against, so the only thing standing between an ad-hoc command and the
target is the hard DoS floor at 100+.

So the protection covers the library, not the operator. That is the weaker half of what the
operator asked for: *"we have to follow by the particular rate limits of the program... All those
things should be hard coded."*

## No violation occurred

Every command dispatched on 2026-07-27 carried `-rl 5`. Roughly **75 HTTP requests to real targets
across the whole session**; peak aggregate ~10 req/s against a global cap of 20, split across
different programs so no single host exceeded 5. The two `subfinder` runs sent **zero** packets to
any target.

The gap is prospective. Nothing would have *stopped* a higher number — it simply was not used.
"I was careful" is not a control, which is the whole point.

## The fix

Two halves, and both are needed:

1. **`scope_compiler.py`** — write `rate_ceiling` (int req/s) into `.scope_lock/enforcement.json`.
   The value already exists as `cfg["rate_value"]`; it is used to rewrite library commands and
   then discarded.
2. **`.claude/hooks/enforce_scope.py`** — parse rate flags from the command, compare against
   `rate_ceiling`, deny when over. The alias table must be duplicated into the hook (it has to
   stay self-contained), mirroring `_RATE_ALIASES` in the compiler:
   `-rate-limit` / `-rl` / `-rate` / `--rate-limit`.

Place the check **before** the soft-boundary early-return, so lowering shields does not also drop
a promise made to a program.

## Two things the fix must NOT quietly skip

- **Delay-based tools are inverted.** `gobuster --delay`, `sqlmap --delay`, `dalfox --delay` set a
  pause between requests, so *smaller* is faster — the opposite comparison. Units differ too
  (`100ms` vs float seconds). Either handle them explicitly or state plainly that they are
  uncovered. Silently missing them would recreate this exact bug in a new place.
- **Threads are not rate**, but concurrency multiplies effective load. Out of scope for this fix;
  worth a separate look.

## Related gap, same discovery

**There is no independent ledger of dispatched commands.** `remote_data.py` tracks the data
lifecycle (encrypt → pull → verify → purge) and reconciles to zero, but nothing records *what
commands were sent*. Asked "prove you stayed under the limit," the only answer available is the
agent's own transcript. That is not an audit trail.

Worth adding: append every dispatched command, engagement, rate flag and timestamp to a local
append-only log at `run_remote()` time.

## Recommendation

Fix both halves together, with mutation tests — plant an over-ceiling command, confirm denial;
restore, confirm a compliant command still passes. This touches the wall, so it gets the full
treatment rather than a quick patch. Deferred deliberately at 06:00 rather than rushed.
