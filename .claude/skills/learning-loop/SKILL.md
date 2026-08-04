---
name: learning-loop
description: Record what this session worked out, so the next one starts from it instead of re-deriving it. Use when the operator corrects you, when a checker turns out to be wrong, when a confident conclusion proves false, or at the end of a working session. Also use to review whether an existing lesson has stopped being true.
---

# The learning loop

The model's weights do not change. What can change is what the next session starts knowing, and
that is entirely a function of what this session bothers to write down.

    python3 global/learning/lessons.py --help

## When to write one

**When the operator corrects you.** Especially a correction you have heard before — that is the
signal that something needs to move from "mentioned" to "written down".

**When you were confidently wrong.** These are the valuable ones. A wrong verdict caught by a
control, a checker that validated itself with its own flawed method, a conclusion drawn from
two-thirds of a function. Far more useful than another technique.

**When a mechanism turns out not to exist.** Prose in a config that nothing enforces. This
workspace produces that failure repeatedly and it is worth its own entry every time.

**Not** for per-engagement findings, test results, or progress. Those belong in that engagement's
`NOTES.md`, `_COVERAGE.md` and `findings/`. This is about how we work, not what we found.

## The ladder, and why it has a way down

| status | meaning |
|---|---|
| `observed` | seen once. Recorded and nothing else. Changes nobody's behaviour. |
| `candidate` | seen twice, or the operator stated it as a rule. Now act on it. |
| `active` | load-bearing enough to be an instruction in the operating context. |
| `retired` | wrong, or no longer true. Kept, with the reason. |

**One occurrence is deliberately not enough.** The operator asked specifically not to have a
passing remark on a bad day become a permanent rule. Two is the threshold because a correction
given twice is already costing time.

**Retiring is as important as promoting.** A stale instruction everyone still follows costs more
than a lesson nobody wrote down. The bwrap memory is the worked example: true when written,
false within a day, and it would have sent the next agent down a dead end that had already cost
almost a full day once.

## Scope, and the operator's actual worry

Each lesson is `engagement`, `platform`, or `general`. The concern raised was getting locked into
a bad loop — something learned in one situation quietly governing every situation, with no way
back.

So scope is a **field, not a location**, and it moves in both directions:

    lessons.py rescope <name> --to platform --because "did not generalise beyond Intigriti"

Narrowing is a first-class action, not a failure. A lesson that turned out to be situational gets
narrowed, keeping the record that it was once believed more widely.

## What you may do alone, and what you may not

**Alone:** add a lesson, add evidence, rescope, retire. All cheap, all reversible, all confined to
this directory.

**Not alone:** promote a lesson into `OPERATING-CONTEXT.md`, `CLAUDE.md`, or a hook. That changes
how every future session behaves. Stage it and let the operator decide:

    lessons.py stage <name>          # writes to _NEEDS-REVIEW/, applies nothing

An agent proposing a rule is fine. An agent quietly rewriting the rules it operates under is not,
and the operator explicitly said they might change their mind about any of it.

## Evidence is the whole argument

Every lesson carries the occasions that produced it — what happened, what the correction was. A
rule traceable to three real events can be judged, argued with, and retracted. A rule with no
evidence is folklore, and folklore is what makes a framework rigid instead of good.

When you add an occurrence, write what actually happened, not a restatement of the rule.

    Bad:   "again gave a vague instruction"
    Good:  "told the operator to run scope_compiler.py status; there is no status subcommand,
            it is show. I invented it rather than checking --help."

## At the start of a session

    python3 global/learning/lessons.py review

Two minutes. It shows what is ready to act on, what is still a single anecdote, and what is
currently active — the last of which deserves doubt precisely because it is being followed
without being re-examined.
