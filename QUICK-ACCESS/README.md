# QUICK-ACCESS

Things you reach for without hunting. In a live workspace this directory also holds the operator's
own paths and command cheat-sheets; those are operator-local and are not part of the framework.

## `opsec_check.py` — run this before testing

    python3 QUICK-ACCESS/opsec_check.py            # local checks, no network traffic
    python3 QUICK-ACCESS/opsec_check.py --net      # + connection guard (reaches out)
    python3 QUICK-ACCESS/opsec_check.py --gate     # + full pre-engagement gate (slow)
    python3 QUICK-ACCESS/opsec_check.py --json     # machine-readable

One command that verifies the protections are actually **on**: the scope wall registered *and
firing*, the engagement's scope lock approved with a rate ceiling, execution resolving to the remote
executor, nothing scanning from this machine, no Anthropic API key present locally, nothing stranded
on the executor, RAM headroom, the operating context loaded, and attribution handles on file.

It is also exposed as the `/opsec-check` skill, and `global/CLAUDE.md` makes it step 6 of the
initialization protocol.

### Three design rules, each of which costs something

1. **UNKNOWN is not PASS.** A check that cannot determine its answer reports `UNKNOWN`, and the run
   does not come back clean. "Could not tell" is the state that hides real failures.
2. **Every check says what it examined.** A clean verdict with no evidence is indistinguishable from
   a check that silently did nothing.
3. **The wall is tested by USE, not by inspection.** Reading `settings.json` proves the hook is
   *listed*. Only handing it a request it must deny proves it *works* — which matters, because this
   framework's scope hook once sat correct but unregistered for six days with nothing appearing to
   be wrong.

Exit code is 0 only when nothing failed and nothing was unknown.

Tests: `testing/test_opsec_check.py`. Every case breaks something and asserts the check catches it,
because a pre-flight that always comes back clean is worse than none.
