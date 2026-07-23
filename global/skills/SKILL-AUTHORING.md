# Skill-authoring guide — a reusable template + checklist

A lightweight, repeatable structure for writing a **new skill** in this workspace. It's a
**starting point, not a straitjacket** — it captures the standard the existing skills already
follow (sharp triggers, explicit ordered steps, a self-check before any hard action). Deviate
whenever a skill genuinely calls for it; the goal is clarity and safety, not ceremony.

Use it when you add any new `/command` skill (under `.claude/skills/<name>/SKILL.md`) or a
methodology/knowledge skill (under `global/skills/...`).

---

## 1. Anatomy of a good skill

**Frontmatter** (the part that decides *when* the skill fires):

```yaml
---
name: <kebab-case-name>            # matches the folder; how it's invoked as /<name>
description: <1–3 sentences. State exactly WHAT it does and WHEN to reach for it. Be
             specific — vague descriptions never fire (or fire wrongly). Name the trigger
             situation, the inputs, and the outcome.>
disable-model-invocation: true     # set TRUE for anything the operator alone should trigger
                                   # (scope changes, anything that widens the wall). Omit/false
                                   # only for skills safe for the model to invoke on its own.
user-invocable: true               # exposes it as a /command
argument-hint: [arg1] [--flag]     # what the operator types after the name
arguments: [arg1, flag]            # names the positional args
---
```

**Body** — ordered, explicit, fail-closed:

- **Step 0 — Resolve inputs / preconditions.** Locate files, validate args. If anything is
  missing, ambiguous, unsigned, or a placeholder → **STOP and ask**. Never infer authorization.
- **Steps 1..N — the work**, in the exact order to do it. Each step concrete enough that two runs
  produce the same result. Prefer numbered steps over prose.
- **A self-verify / evaluation block** *before* any hard-stop, write, or commit: how does the
  agent know the output is internally consistent and correct? (JSON parses, lists are in lockstep,
  nothing targets out-of-scope, no self-deny, hashes match.) This is a machine self-check — NOT
  operator approval.
- **A hard STOP for operator approval** wherever the skill changes what's allowed. State clearly
  what's presented for review and that the skill never self-approves.

---

## 2. The checklist (tick before you ship a skill)

- [ ] `name` matches the folder; `description` names a **specific** trigger situation, not a topic.
- [ ] `disable-model-invocation: true` if the operator alone should run it (anything that widens
      scope, adds a technique, or touches the enforcement wall).
- [ ] Steps are **ordered and concrete** — no "figure it out" gaps.
- [ ] **Fail-closed**: missing/ambiguous input → STOP, never guess.
- [ ] A **self-verify block** exists before any write/commit/hard-stop.
- [ ] A **STOP-for-approval** exists wherever the skill changes what's permitted; it never
      self-approves.
- [ ] Stays inside policy: nothing it emits can target out-of-scope assets or violate the
      workspace's hard rules / operational constraints.
- [ ] Artifacts it writes are kept **in lockstep** (e.g. a human-readable file + its compiled
      machine profile always agree).
- [ ] Reads of read-only sources (framework, production tools) never mutate them.

---

## 3. Skeleton — copy this into a new `SKILL.md`

```markdown
---
name: <name>
description: <what it does + when to use it — specific triggers, inputs, outcome>
disable-model-invocation: true
user-invocable: true
argument-hint: [target] [--flag]
arguments: [target, flag]
---

# /<name> — <one-line purpose>

<1–2 sentences: what this produces and when the operator runs it.>

## Step 0 — Resolve inputs (fail closed)
- <locate/validate>. If missing/ambiguous/placeholder → STOP and ask.

## Step 1..N — <the work, ordered>
- <concrete action>

## Step N+1 — Self-verify before presenting (machine check, NOT approval)
- <checks that the output is internally consistent — do not present until all pass>

## Final — HARD STOP for operator review (if it changes what's allowed)
Present <what>; STOP; act only AFTER explicit approval. Never self-approve.
```

---

## 4. Notes specific to this workspace

- Anything that gates or widens **offensive tooling** must be **operator-triggered and
  fail-closed** — mirror `/generate-scope` and `/add-ttp`. The PreToolUse hook is the hard wall;
  a skill's job is to compile the operator's approval into that wall, never to bypass it.
- Distinguish **hook-enforced** rules (binary + asset + deny-list) from **convention-enforced**
  ones (command shape, e.g. rate-limit flags / attribution header). If a skill relies on a
  convention, say so explicitly so it isn't mistaken for a hard guarantee.
- Keep real engagement/lab data inside that engagement's own folder; `global/` holds only reusable
  config and skills.
```
