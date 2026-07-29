---
name: opsec-check
description: Verify the operational protections are actually on before testing — the scope wall registered AND firing, the engagement's scope lock approved with a rate ceiling, execution resolving to the remote executor, nothing scanning locally, no Anthropic API key on this machine, no artifacts stranded on the box, RAM headroom, and the operating context loaded. Run it before the first request of a session, and again after anything changes the machine's posture.
user-invocable: true
argument-hint: [--net] [--gate]
arguments: [flag, flag]
---

# /opsec-check — is it safe to start?

## This is a thin wrapper. The implementation is code.

    python3 QUICK-ACCESS/opsec_check.py            # local checks, no network traffic
    python3 QUICK-ACCESS/opsec_check.py --net      # + connection guard (makes outbound requests)
    python3 QUICK-ACCESS/opsec_check.py --gate     # + the full pre-engagement gate (slow)
    python3 QUICK-ACCESS/opsec_check.py --json     # machine-readable

**Run the program. Do not reimplement its checks, and do not substitute your own reading of the
files for its verdict.** Every one of these checks existed before as a paragraph somewhere; scattered
across five tools and a document, they got run selectively — and the one skipped was the one
failing. The scope wall sat correct-but-**unregistered** for six days because nothing ever asked "is
it registered?" in the same breath as "is it correct?".

## When to run it

- **Before the first request of any testing session.** This is the main one.
- After anything that changes machine posture: a settings change, a new engagement, a reboot, a
  network change, a session that started somewhere unusual.
- Before reporting that testing has stopped cleanly — `--gate` also covers the executor.
- Any time the operator says "run the opsec check" or "perform an opsec check."

It makes **no network requests** by default, so running it is cheap and carries no traffic risk.
`--net` and `--gate` do reach out and are opt-in for that reason.

## Reading the result

`CLEAR` means every check passed or warned. Anything else means **do not start testing yet**.

- **FAIL** — a protection is off. Fix it; do not proceed and do not work around it.
- **UNKNOWN** — the check could not determine an answer. **This is not a pass.** "Could not tell" is
  the state that hides real failures, so it keeps the run from coming back clean by design.
- **WARN** — worth reading, does not block. A missing engagement selection is a warning because
  framework work legitimately has none; testing does not.

Exit code is 0 only when nothing failed and nothing was unknown.

## What it does not cover

It checks that the **protections are on**. It cannot check that you are testing the right things,
that a program's path restrictions are being respected by hand, or that an attribution header
matches the live policy — those are judgement, and it says so rather than implying coverage it does
not have.

Tests: `testing/test_opsec_check.py` — every case breaks something and asserts the check catches it,
because a pre-flight that always comes back clean is worse than none.
