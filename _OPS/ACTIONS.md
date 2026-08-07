# Operator action queue

Everything that only the operator can do. One row each, newest first, and **every row has a state**
— that is what stops this becoming another pile of files nobody can triage.

`OPEN` · `BLOCKED` (waiting on something else) · `DONE` · `DROPPED` (with the reason)

An item belongs here only if an agent genuinely cannot do it: an approval, a credential, a signup,
a purchase, a `git push`, a decision that widens scope. Everything else is just work, and work does
not go in a queue addressed to someone else.

Detail lives in the engagement's `_NEEDS-REVIEW/NN_*.md`; this is the one-line view of all of it.
Close rows as they resolve — an item left `OPEN` after it is done is exactly as misleading as a
stale file.

| Raised | State | What | Why it matters / what a yes unlocks |
|---|---|---|---|
| 2026-01-01 | **DROPPED** | _template row — replace with real items_ | Kept only so the table shape is obvious. Delete it once there is a real row. |
