# 01 — There is no independent log of dispatched commands

**Status:** 🟡 OPEN · **Raised:** 2026-07-27
**Sibling gap (rate ceiling) — CLOSED the same day, enforced in the wall, 12/12 mutation-tested.**

## The gap

`remote_data.py` tracks the DATA lifecycle — encrypt, pull, verify checksum, purge, ledger — and
reconciles to zero outstanding. Nothing records **what commands were sent**.

Asked "prove you stayed under the rate limit," the only available answer is the agent's own
transcript. That is not an audit trail. An agent asserting its own compliance is precisely the
thing that needs independent evidence.

This surfaced alongside the rate-ceiling gap. That one is now enforced by the wall, so an
over-limit command cannot run. This one is different: it is not about prevention, it is about
being able to **show** what happened afterwards.

## The fix

Append to a local, append-only log inside `run_remote()`, at dispatch time, after the scope check
passes and before the SSH:

```
timestamp (UTC) · engagement · executor · the full command · rate flags parsed out · rc
```

Local only — never on the box, which is transient and gets purged. Append-only, same discipline as
`BREAKTHROUGH_LEDGER.md`, so entries cannot be quietly rewritten.

Log the DENIED ones too. A refusal is the more interesting record: it shows the wall firing, and a
log that only contains successes cannot distinguish "never attempted" from "attempted and blocked".

## Why it matters beyond bookkeeping

Every constraint in this workspace is enforced by the wall — scope, binaries, the hard floor, and
now the rate ceiling. But enforcement leaves no receipt. If a program ever asks what we sent and
when, or if the operator wants to check a session without reading a transcript, there is currently
nothing to point at.
