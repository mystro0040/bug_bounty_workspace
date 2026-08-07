# HANDOFF — read this first

Updated: **2026-01-01 00:00 UTC** · by: template · machine: —

> **This is the template.** The first real session overwrites it entirely. Keep the shape: this
> file is an **index**, not a record. It says where we are and what to do next; everything it
> describes lives somewhere else, and that somewhere else is the truth. If this file and an
> engagement's `_STATUS.md` disagree, the engagement wins.

New here? Read `_OPS/README.md` once — it explains why things are where they are.

## Where we are

_One short paragraph. Opsec state, test state, anything in flight, anything in triage._

## Do this next, in this order

_Numbered, most valuable first. Point at the engagement file that holds the detail — do not restate
it here. "See `engagements/<eng>/_STATUS.md`" is the correct level of detail for this file._

## What is blocked, and on whom

Everything only the operator can do lives in **`_OPS/ACTIONS.md`** with a state. Do not re-derive
it here and do not start a parallel list. Name the top two or three and link.

## Things that will bite you

_Tooling quirks, wall behaviours, traps a fresh agent would hit. Short bullets. This section earns
its place — it is the one part of a handoff that reliably saves the next session real time._

## Where things live

| Looking for | Go to |
|---|---|
| What is true about one program | `engagements/<eng>/_STATUS.md`, then `_PLAN.md` and `_COVERAGE.md` |
| What the operator owes us | `_OPS/ACTIONS.md` |
| What happened in a past sitting | `_OPS/sessions/YYYY-MM-DD-N.md` |

## Before you finish your session

Write `_OPS/sessions/<today>-N.md`, update any `ACTIONS.md` rows you resolved, overwrite this file,
then run `python3 _OPS/check_ops.py`. Do not create a second handoff with a date in its name — that
is the habit this structure exists to kill.
