#!/usr/bin/env python3
"""Refuse to write a "finished" status while permitted testing remains.

WHY THIS IS A HOOK AND NOT A SENTENCE IN THE CONFIG

"Keep testing; do not stop to ask permission for work you are already allowed to do" has been in
the agent configuration for weeks. It is written precisely. It names the exact moment it fails —
the end of a report, where a pause in NARRATION gets mistaken for a pause in WORK. The operator has
repeated it many times over many sessions.

It kept failing anyway, including twice in the session that produced this file.

It failed because it is prose, and prose has to survive two hundred tool calls of accumulated
context to reach the moment it applies. Every rule in this workspace that actually holds is code:
the scope wall, the never-ship gate, the control gate on findings, the attribution-header check.
Every rule that keeps failing is addressed to a reader.

So: the same rule, as code, at the moment it matters.

THE CHOKEPOINT

Stopping has an artifact. `_STATUS.md` gets `state: DONE` or `state: WAITING_FOR_OPERATOR`. That
write is the act of declaring the session finished, and it is the thing this refuses.

WHY IT IS A SEPARATE FILE FROM THE SCOPE WALL

`enforce_scope.py` is a SAFETY control — it decides what may be targeted. This is a DISCIPLINE
control; being wrong here wastes time, being wrong there is an unauthorised request against
somebody's systems. Putting this logic in that file would mean a bug in a productivity gate could
break scope enforcement. They stay separate.

WHY IT NOW WATCHES Bash TOO (amended 2026-08-06)

This used to be registered for the file-editing tools only, and said so here, with the reasoning
that it should never sit in the path of a command. That reasoning was fine and the conclusion was
wrong, because it guarded a doorway rather than a destination: `cat > …/_STATUS.md <<'EOF'` writes
exactly the file this exists to protect and the hook never saw it. It was found by walking straight
through the gate while not trying to — the failure mode that matters, since anyone deliberately
avoiding a discipline gate has already decided not to be helped by it.

So it watches Bash as well, and the cost is kept where the old reasoning wanted it: a Bash command
that does not redirect into a `_STATUS.md` is allowed by a single regex miss, before anything is
parsed, imported or run.

Closing it took two passes and the second is the instructive one. The first attempt caught the
heredoc and still let `echo 'state: DONE' >> …` and `… | tee …` through, because the `state:`
pattern was anchored to the start of a line — true of a file, false of a command. **A control ported
to a new input has to be re-tested against that input, not assumed to carry over.**

FAIL OPEN, LOUDLY — and why that is right HERE and wrong for the wall

If this cannot determine an answer, it ALLOWS and says so in the reason. That is the opposite of
the scope wall, which fails closed, and the difference is the cost of being wrong: a wall that
wrongly allows sends traffic somewhere it should not, while a gate that wrongly allows lets a
status file be written. Failing closed here would block a legitimate stop because a helper moved,
which is exactly how a checker earns a reputation for crying wolf and gets removed.

THERE IS NO OVERRIDE, AND ONE EXIT

The way past is to do the thing that should have happened anyway: test it, or record why it cannot
be tested. Both leave the next session better off than an override would.

The one exception is `state: PAUSED_BY_OPERATOR`, which is never gated. The rule is "do not stop on
your own initiative while permitted work remains" — not "never stop". When the operator says wind
down, that is their call and this has no opinion.
"""
import json
import os
import re
import subprocess
import sys

HOOK_EVENT = "PreToolUse"

GATED_STATES = ("done", "waiting_for_operator")
OPERATOR_PAUSE = "paused_by_operator"

PLAN_CANDIDATES = [
    os.path.expanduser("~/Workspace/Production_Ready/public/Offensive_Security/"
                       "bug-bounty-execution-framework/utilities/engagement/plan.py"),
    os.path.expanduser("~/Workspace/Production_Ready/private/Offensive_Operations/"
                       "bug-bounty-execution-framework/utilities/engagement/plan.py"),
]


def emit(decision, reason=""):
    out = {"hookSpecificOutput": {"hookEventName": HOOK_EVENT,
                                  "permissionDecision": decision}}
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    sys.stdout.write(json.dumps(out))
    sys.exit(0)


# A shell redirect into `_STATUS.md`. Found 2026-08-06, by walking straight through this gate
# without noticing: `cat > …/_STATUS.md <<'EOF'` sets `state: WAITING_FOR_OPERATOR` and the hook
# never sees it, because the matcher only covered the file-editing tools. The gate had 35 passing
# tests and a registration proven live, and was still trivially avoidable — not by anyone trying
# to avoid it, which is the point. A control that only guards the tidy path guards nothing.
#
# Matches the redirect forms a shell actually offers (`>`, `>>`, `tee`) against a path ending in
# the status file. Deliberately not a general shell parser: this asks one narrow question, and
# something that tried to understand arbitrary shell would fail open in ways nobody could predict.
_SHELL_WRITE = re.compile(
    r"(?:>>?\s*|tee\s+(?:-a\s+)?)(?P<path>[^\s;|&'\"]*_STATUS\.md)")


def bash_status_writes(command):
    """Every `_STATUS.md` a Bash command would write, with the text going into it.

    The text is the WHOLE command, heredoc body included. That is deliberate over-matching: this
    gate only ever looks for a `state:` line, and a command mentioning one while redirecting into
    a status file is the thing being guarded either way.
    """
    return [(m.group("path"), command) for m in _SHELL_WRITE.finditer(command or "")]


def written_text(tool_name, tool_input):
    """The text this call would put into the file."""
    if tool_name == "Write":
        return tool_input.get("content", "") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string", "") or ""
    if tool_name == "MultiEdit":
        return "\n".join((e or {}).get("new_string", "")
                         for e in (tool_input.get("edits") or []))
    return ""


def declared_state(text, anywhere=False):
    """The `state:` this write sets, lowercased, or None.

    `anywhere` is for shell commands. In a file the line is a line, so anchoring to the start of
    one is right and keeps prose that merely mentions a state from tripping the gate. In a command
    it is not: `echo 'state: DONE' >> …/_STATUS.md` puts it mid-line behind a quote, and the
    anchored pattern misses it — which is how two of the three redirect forms walked through this
    gate on the first attempt to close it. Unanchored matching is safe here because the caller
    only acts on a state that is in the gated set.
    """
    pattern = r"state\s*:\s*([A-Za-z_]+)" if anywhere else r"^\s*state\s*:\s*([A-Za-z_]+)"
    m = re.search(pattern, text, re.M)
    return m.group(1).strip().lower() if m else None


def engagement_from_path(path):
    """`…/engagements/programs/x/y/z/_STATUS.md` -> `programs/x/y/z`."""
    parts = os.path.normpath(os.path.abspath(path)).split(os.sep)
    if "engagements" not in parts:
        return None
    i = len(parts) - 1 - parts[::-1].index("engagements")
    rest = parts[i + 1:-1]
    return "/".join(rest) if rest else None


def plan_tool():
    for p in PLAN_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


_COVERAGE_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([a-z]+)\s*\|")

# Phrases that assert there is nothing left. Deliberately narrow: these are claims, not
# descriptions. "walled", "blocked" and "needs an account" are NOT here — they describe a
# reason and are exactly what should be written instead.
_EXHAUSTION = re.compile(
    r"\b(exhaust(?:ed|ive)|nothing (?:left|more|further) to test|no (?:surface|classes?) remain"
    r"|fully tested|nothing untested|all classes closed|no untested|surface is complete"
    r"|tested to exhaustion)\b", re.I)


def untested_rows(engagement):
    """How many SURFACE x CLASS rows this engagement's own ledger records as untested.

    Fails OPEN on absolutely anything. This is a discipline gate, not a safety one — a bug here
    must never be able to block real work, and a crashing hook is worse than an absent one.
    """
    try:
        bucket = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(bucket, "engagements", engagement, "_COVERAGE.md")
        n = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _COVERAGE_ROW.match(line)
                if m and m.group(3).strip().lower() == "untested" \
                        and m.group(1).strip().lower() != "surface":
                    n += 1
        return n
    except Exception:                                             # noqa: BLE001
        return 0                      # no ledger / unreadable -> nothing to contradict


def exhaustion_claim(text):
    return bool(_EXHAUSTION.search(text or ""))


def cites_count(text, n):
    """Did the writer actually quote the real number? Anything else is memory, not evidence."""
    return re.search(r"\b%d\b" % n, text or "") is not None


def main():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        emit("allow")

    tool = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}

    if tool == "Bash":
        writes = bash_status_writes(tool_input.get("command") or "")
        if not writes:
            emit("allow")
        path, text = writes[0]
        is_shell = True
    elif tool in ("Write", "Edit", "MultiEdit"):
        path = tool_input.get("file_path") or ""
        if os.path.basename(path) != "_STATUS.md":
            emit("allow")
        text = written_text(tool, tool_input)
        is_shell = False
    else:
        emit("allow")

    # --- THE PROSE HOLE, closed 2026-08-07 ------------------------------------------------
    # This gate fired on `state: DONE`. The failure it kept missing never wrote DONE: it kept
    # `state: RUNNING` and claimed IN PROSE that a surface was "exhausted" — to the operator, and
    # into this very file — while the coverage ledger held 2,052 untested rows across 26 approved
    # engagements. A claim with no artifact cannot be gated, but a claim written INTO the artifact
    # can be, and that is where it gets written down for the next session to believe.
    #
    # This does not ban the word. A scoped claim ("the unauthenticated surface is exhausted, the
    # rest needs an account") is often exactly right. What it bans is claiming it WITHOUT having
    # looked: the claim is allowed only when the text also carries the real untested count, which
    # cannot be written without consulting the ledger. Evidence beside the assertion, or neither.
    engagement = engagement_from_path(path)
    if engagement:
        n_untested = untested_rows(engagement)
        if n_untested > 0 and exhaustion_claim(text) and not cites_count(text, n_untested):
            emit("deny",
                 "You are writing an EXHAUSTION CLAIM into a status file while the coverage "
                 f"ledger for this engagement records {n_untested} untested surface x class "
                 "row(s).\n\n"
                 "The claim may still be correct if it is SCOPED — 'the unauthenticated surface "
                 "is exhausted; the rest needs an account' is a fine sentence. But it has to be "
                 "made against the evidence, not from memory, because memory is what has been "
                 "wrong every previous time.\n\n"
                 "Do one of these:\n"
                 f"  * scope the claim and state the number: '... {n_untested} rows remain "
                 "untested, listed below / blocked on X'\n"
                 "  * record what you actually tested first:\n"
                 "      plan.py cover --engagement <eng> --surface <s> --class <c> --state clean "
                 "--note '<why>'\n"
                 "  * drop the word and describe what is blocked instead\n\n"
                 "See the whole picture:  python3 _OPS/surface_report.py --detail "
                 f"{engagement.rsplit('/', 1)[-1]}")

    state = declared_state(text, anywhere=is_shell)
    if state is None or state == OPERATOR_PAUSE or state not in GATED_STATES:
        emit("allow")

    if not engagement:
        emit("allow", "[keep-testing gate] could not work out which engagement this status file "
                      "belongs to, so it was not checked. Allowing — this is a discipline gate, "
                      "not a safety one.")

    tool_path = plan_tool()
    if not tool_path:
        emit("allow", "[keep-testing gate] plan.py not found on this machine, so 'is there "
                      "untested surface left' could not be answered. Allowing, but the check did "
                      "NOT run — do not read this as a clean bill of health.")

    try:
        proc = subprocess.run([sys.executable, tool_path, "may-i-stop",
                               "--engagement", engagement],
                              capture_output=True, text=True, timeout=60)
    except Exception as exc:                                      # noqa: BLE001
        emit("allow", f"[keep-testing gate] could not run the check ({type(exc).__name__}). "
                      "Allowing; the check did NOT run.")

    if proc.returncode == 0:
        emit("allow")

    detail = (proc.stdout or proc.stderr or "").strip()
    emit("deny",
         "You are writing a FINISHED status while there is still permitted work on this "
         "engagement.\n\n"
         f"{detail}\n\n"
         "This is the rule you have been given many times, as code instead of prose, because "
         "prose kept losing. There is no override and you should not look for one — the way "
         "past is to test the thing, or to record why it cannot be tested. Either leaves the "
         "next session better off.\n\n"
         "If the OPERATOR told you to stop, that is their call and this gate has no say: use "
         "`state: PAUSED_BY_OPERATOR`.")


if __name__ == "__main__":
    main()
