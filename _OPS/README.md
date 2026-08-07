# `_OPS/` — the coordination layer

**Read `HANDOFF.md` first. It is always at that exact path.**

This directory exists because three different kinds of writing were being mixed together with
only one of them having a defined home, and the other two landed wherever the agent happened to
put them. In practice that produced dozens of loose files on the operator's desktop under a dozen invented
prefixes, none carrying a state, so nobody could tell what was still live.

## The three kinds, and where each one goes

| Kind | Home | Lifetime |
|---|---|---|
| **Engagement state** — what is true about one program | `engagements/<eng>/` (`_STATUS.md`, `_PLAN.md`, `_COVERAGE.md`, `NOTES.md`, `BREAKTHROUGH_LEDGER.md`, `_NEEDS-REVIEW/`) | permanent, lives with the engagement |
| **Session narrative** — what happened in one sitting, across everything | `_OPS/sessions/YYYY-MM-DD-N.md` | write-once history |
| **Operator actions** — anything only the operator can do | `_OPS/ACTIONS.md`, one row each | until closed |

Plus exactly one pointer file:

| `_OPS/HANDOFF.md` | where we are, what is next | overwritten every session |

## The rule that actually prevents clutter

**Every fact has exactly one home, and the handoff holds none of them.**

`HANDOFF.md` is an INDEX. It says where to look and what to do next. It does not restate what an
engagement's `_STATUS.md` already says. The moment the handoff starts carrying content, that
content exists in two places, they drift, and the next agent has to work out which one is true.
That is the whole disease.

If you catch yourself pasting a finding, a host list or a verdict into the handoff — stop. It
belongs in the engagement. Link to it.

## Naming, and why it is fixed

- **`HANDOFF.md` has no date in its name, ever.** A dated handoff can be created again tomorrow
  next to today's, and then there are five and nobody knows which is current. One path, always
  the same, overwritten. The old versions live in the session logs and in git.
- **There is no `superseded/` folder.** It was a workaround for dated filenames. Fixed names do
  not need one.
- **Session logs are `YYYY-MM-DD-N.md`** — N is the sitting number that day. Never read in bulk;
  they answer "what did we do on the 7th" and nothing else.

## `ACTIONS.md` — the thing that replaces loose Desktop files

One table. Every row has a **state**, and that is the point: an item nobody closed is visible as
open rather than as a file lying around looking like litter.

States: `OPEN` · `BLOCKED` · `DONE` · `DROPPED` (with a reason).

An action goes here when **only the operator can do it** — an approval, a credential, a signup, a
purchase, a decision that widens scope, a `git push`. Anything an agent can do itself is not an
action, it is just work.

Per-engagement asks still get their `_NEEDS-REVIEW/NN_*.md` file, because that is where the full
reasoning belongs. `ACTIONS.md` carries the one-line version and links to it. The queue is for
seeing everything at once; the file is for the detail.

## The Desktop — the line is WHO it is for

The Desktop is the operator's workspace, not a dumping ground and not a filing system.

**Legitimately theirs:** a runbook of commands to paste, a walkthrough for verifying a finding by
hand, an approval block, a decision they need to make with the context to make it. These are
things the operator DOES, and putting them where they work is correct. Keep it to one file per
task, name it for the action, and add a matching row in `ACTIONS.md` so an agent knows it exists
and can see when it is closed.

**Never theirs:** agent handoffs, session state, coverage notes, engagement status. Those are how
agents coordinate with each other, and the operator should not have to store, sort or scroll them.
That is what put eight dated `PICK-UP-HERE-*.md` files and a `superseded/` folder in front of
someone who never asked for them.

The test is simple: **if the reader is another agent, it goes in the bucket.** If the reader is the
operator, the Desktop is fine — but derive it from what is already here rather than authoring it
separately, or it becomes a second source of truth that drifts.

## What a session does

1. **Start:** read `HANDOFF.md`, then the `_PLAN.md` of whatever it names.
2. **During:** engagement facts go to the engagement, as they happen. Nothing accumulates in
   memory waiting for a write-up.
3. **End:** write `sessions/YYYY-MM-DD-N.md`, update any `ACTIONS.md` rows, overwrite
   `HANDOFF.md`.

`python3 _OPS/check_ops.py` verifies the shape of all this. It is a WARN, never a blocker — an
untidy record is a debt, not an unsafe condition, and it must never stop testing.
