---
name: verification-packet
description: Build the operator's verification packet for a finding — an anonymised explainer they can hand to an outside AI to listen to, plus a private step-by-step walkthrough for verifying the bug by hand and capturing evidence. Use before submitting any report. Enforces the public/private split mechanically.
---

# Verification packet

The operator does not submit a finding they have not personally understood and personally
verified. Several programs require exactly that in writing — Intigriti's code of conduct says
*"personally identify and verify the vulnerability before submitting it"*, and one HackerOne
program states that reports "not manually reproduced, or [without] valid verification result
screenshots will be directly rejected by the platform, and no reasons for rejection will be
provided."

This skill builds what makes that possible: an explainer the operator can listen to, and a
walkthrough they can follow.

**It is also the thing that makes a report honest.** A report saying "verified manually by the
reporter" is only true if they did. This produces the steps; running them is what makes the
sentence true.

## Why it is not called "verify"

`findings_store.py verify` means *re-hash both copies and prove nothing rotted*.
`scope_compiler.py verify` means *are the compiled artifacts self-consistent*.

A third meaning for the same word is how a checker gets run for the wrong reason and its output
misread. This produces a **packet**; that is what it is called.

## Structure

```
~/Desktop/temp/verify-findings/<NN>-<slug>/
    .engagement                    which engagement — read by the checker
    public/
        EXPLAIN-listen.md          spoken-word explainer + a prompt telling the AI: no
                                   formatting, no code blocks, two-speaker, ~8–10 min
        EXPLAIN-read.md            written explainer — analogy, severity, how to report it
    private/
        VERIFY.md                  the real walkthrough: real hosts, real commands
        README.md                  index, thirty-second version, why this one
```

**`public/` explains the BUG CLASS. `private/` covers THIS INSTANCE.** The operator hands
`public/` to an outside AI to have it read aloud; that is a third party, so nothing identifying
may be in there.

## The boundary is checked, not trusted

```bash
python3 .claude/skills/verification-packet/packet.py new   <slug> --engagement <eng>
python3 .claude/skills/verification-packet/packet.py check <slug>
python3 .claude/skills/verification-packet/packet.py list
```

`check` derives the forbidden terms from the engagement's **own scope-lock** — every host and
wildcard it is authorised against, plus each distinctive label, the program slug, the platform,
and the operator's handles from `operator-identity.md`. Nothing is hardcoded, so a new engagement
is covered the day it compiles.

- **LEAK** — an identifying term appears in `public/`. Blocking. Do not hand the packet to
  anyone until it is gone.
- **platform warning** — a third-party platform name (Firebase, Vercel, Auth0 …). Not blocking:
  millions of sites use these, so naming one is not disclosure on its own. But platform *plus*
  bug class narrows the target, so it is surfaced and the operator decides. Prefer
  "a static-site hosting platform" where the explainer does not genuinely need the name.

Matching is word-boundary only. Substring matching produced a false positive on the first real
run — "exact" inside "exactly" — and a checker that cries wolf is one that gets ignored, which
is worse than not having it.

**Run `check` before the packet is handed anywhere.** It is mutation-tested: planting
`auth.<program>.com` into a public file makes it fail.

## Writing the pieces

### `public/EXPLAIN-listen.md`

This is listened to, not read. The prompt at the top must forbid formatting explicitly — no
markdown, headings, bullets, tables, code blocks, asterisks, backticks, URLs, or file paths.
Anything that reads aloud as punctuation salad has to go.

Then plain spoken prose covering: how the thing normally works · what goes wrong · a
physical-world analogy · why it matters · **what is proven versus what is only suspected** ·
how it is fixed · where the pattern recurs elsewhere.

The analogy is the part that makes it stick. Spend effort there.

End with how it connects to the wider picture — that is what turns a bug explanation into
something the operator can reason from next time.

### `public/EXPLAIN-read.md`

Same content, structured for the eye. Tables and diagrams-in-words are fine here. Include a
severity table and a section on how to report the class well.

### `private/VERIFY.md`

- Every command **read-only**. Say so.
- State the expected output for each step so the operator knows what a match looks like.
- **Include a counter-example step** — the same platform or mechanism working correctly
  elsewhere. It converts "something is broken" into "this specific thing is broken," and it is
  the cheapest credibility in the whole report.
- Flag anything that could be misread. If a step needs `curl -k`, explain *why* and that it is a
  separate issue, so the two do not get conflated in the report.
- Open with the program-page questions that could make the whole finding moot — an exclusion
  clause, an AI-disclosure requirement. Better to spend thirty seconds there than an hour on a
  report that gets closed as not-applicable.
- Close with an honesty check: what the report will claim, and what it will not.

## Where things actually live

The packet directory is under `~/Desktop/temp/` and **the operator deletes it when done.** That
is correct for a scratch space and wrong for half of what ends up in it:

| File | Lifetime | Why |
|---|---|---|
| `public/EXPLAIN-*.md` | **Permanent** | They describe a bug *class*, not an instance. The same dangling-DNS explainer serves every future dangling-DNS finding on any program. Rewriting it each time is waste. |
| `private/VERIFY.md` | **Permanent** | It is the record of *how a finding was checked*. That belongs with the finding, next to its evidence. |
| everything else | disposable | Working state. |

```bash
python3 packet.py promote <slug>
```

Copies — never moves, so the working directory keeps working:

- explainers → `global/bug-class-explainers/<bug-class>/` (keyed by class, not by the order the
  operator happened to work things)
- `VERIFY.md` → `engagements/<eng>/06_Proof_of_Concept_and_Impact/verification/`

**`promote` refuses if `check` would fail.** The explainer library is anonymised by construction
and gets propagated to a public repo, so a leaking explainer must never reach it.

Before writing a new explainer, **look in `global/bug-class-explainers/` first** — the class may
already be covered, and then the packet only needs its `private/` half.

## Working with the operator

1. Pick the finding and say which platform, so they can open the submit form.
2. Build the packet. Tell them to **listen first** — the walkthrough is obvious once the analogy
   lands, and they will be able to defend the report if a triager pushes back.
3. They run `private/VERIFY.md` and report what matched.
4. They paste the program's report template.
5. Write the report to **their** fields, using **their** verification output.
6. They read it, change anything that is not true or not their voice, and submit.

Never pre-fill the verification sentence. It is theirs to make true.

## Numbering

`01-`, `02-`, … in the order they are worked, not by severity. The slug describes the **bug
class**, not the target — `01-dangling-dns-delegation`, not `01-windsurf-auth`. The directory
name itself has to survive being read over someone's shoulder.
