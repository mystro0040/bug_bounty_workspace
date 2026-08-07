#!/usr/bin/env python3
"""Verify the coordination layer still has its shape.

WHY THIS IS CODE. The convention it checks was written down once before, in prose, and produced
48 loose files on the operator's Desktop under twelve invented prefixes with no states. A rule
nothing enforces lasts about a week here; that is the characteristic failure in this workspace.

WARN, NEVER FAIL. An untidy record is a debt, not an unsafe condition, and it must never be a
reason to stop testing. Exit code is 0 unless the layer is structurally missing.
"""
import datetime
import os
import re
import sys

OPS = os.path.dirname(os.path.abspath(__file__))
BUCKET = os.path.dirname(OPS)
SESSIONS = os.path.join(OPS, "sessions")

OK, WARN, FAIL = "  OK  ", " WARN ", " FAIL "
rows = []


def rec(level, name, detail):
    rows.append((level, name, detail))


def check_required_files():
    for fname in ("HANDOFF.md", "ACTIONS.md", "README.md"):
        p = os.path.join(OPS, fname)
        if not os.path.exists(p):
            rec(FAIL, fname, "missing — the layer is not intact")
        elif os.path.getsize(p) < 200:
            rec(WARN, fname, "suspiciously small (%d bytes)" % os.path.getsize(p))
        else:
            rec(OK, fname, "present (%d bytes)" % os.path.getsize(p))


def check_no_dated_handoffs():
    """The single most important rule: exactly one handoff, and its name carries no date."""
    # `sessions/archive/` is the sanctioned home for the pre-_OPS dated handoffs. Flagging it
    # would make this check cry wolf permanently, and a check that is always noisy is one that
    # gets ignored — which buries the real signal it exists to raise.
    archive = os.path.join(SESSIONS, "archive")
    strays = []
    for base, dirs, files in os.walk(BUCKET):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "_sync")]
        if os.path.abspath(base).startswith(os.path.abspath(archive)):
            continue
        for f in files:
            # The disease is a DATED handoff, because a dated name can always be created again
            # next to today's. Match precisely that: a markdown file whose name is handoff-ish
            # AND carries a date. A vendored `handoff_worker.go` and an engagement's
            # `test-accounts-HANDOFF.md` are neither, and flagging them is how a check earns
            # the right to be ignored.
            if not f.lower().endswith(".md"):
                continue
            if (re.search(r"(HANDOFF|PICK-?UP-?HERE)", f, re.I)
                    and re.search(r"\d{4}-\d{2}-\d{2}", f)):
                strays.append(os.path.relpath(os.path.join(base, f), BUCKET))
    if strays:
        rec(WARN, "one handoff only",
            "%d dated/duplicate handoff file(s) found — fold them into _OPS/sessions/ and delete: %s"
            % (len(strays), ", ".join(strays[:4]) + (" …" if len(strays) > 4 else "")))
    else:
        rec(OK, "one handoff only", "no dated or duplicate handoff files anywhere in the bucket")


def check_handoff_freshness():
    p = os.path.join(OPS, "HANDOFF.md")
    if not os.path.exists(p):
        return
    txt = open(p, encoding="utf-8", errors="replace").read()
    m = re.search(r"Updated:\s*\*\*([0-9]{4}-[0-9]{2}-[0-9]{2})", txt)
    if not m:
        rec(WARN, "handoff dated", "no `Updated: **YYYY-MM-DD` line — a handoff with no date "
                                   "cannot be told from a stale one")
        return
    try:
        d = datetime.date.fromisoformat(m.group(1))
    except ValueError:
        rec(WARN, "handoff dated", "unparseable date %r" % m.group(1))
        return
    age = (datetime.date.today() - d).days
    if age > 3:
        rec(WARN, "handoff fresh", "last updated %s (%d days ago) — sessions have run since?"
            % (m.group(1), age))
    else:
        rec(OK, "handoff fresh", "updated %s" % m.group(1))


def check_actions_have_states():
    p = os.path.join(OPS, "ACTIONS.md")
    if not os.path.exists(p):
        return
    valid = ("OPEN", "BLOCKED", "DONE", "DROPPED")
    bad, counts = [], {v: 0 for v in valid}
    for line in open(p, encoding="utf-8", errors="replace"):
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0].lower().startswith(("raised", "---")) or set(cells[0]) <= {"-"}:
            continue
        state = cells[1].replace("*", "").strip().upper()
        if state in counts:
            counts[state] += 1
        else:
            bad.append(cells[2][:50] if len(cells) > 2 else line[:50])
    if bad:
        rec(WARN, "actions have states",
            "%d row(s) with no valid state: %s" % (len(bad), "; ".join(bad[:3])))
    else:
        rec(OK, "actions have states",
            "open=%d blocked=%d done=%d dropped=%d"
            % (counts["OPEN"], counts["BLOCKED"], counts["DONE"], counts["DROPPED"]))


def check_session_log_naming():
    if not os.path.isdir(SESSIONS):
        rec(FAIL, "sessions/", "missing")
        return
    good = re.compile(r"^\d{4}-\d{2}-\d{2}-\d+\.md$")
    files = [f for f in os.listdir(SESSIONS) if f.endswith(".md")]
    bad = [f for f in files if not good.match(f)]
    if bad:
        rec(WARN, "session log naming",
            "%d misnamed (want YYYY-MM-DD-N.md): %s" % (len(bad), ", ".join(sorted(bad)[:4])))
    else:
        rec(OK, "session log naming", "%d session log(s), all well-named" % len(files))


def check_handoff_is_an_index():
    """The anti-duplication rule. A handoff that grows is one that has started carrying content."""
    p = os.path.join(OPS, "HANDOFF.md")
    if not os.path.exists(p):
        return
    n = len(open(p, encoding="utf-8", errors="replace").read().split())
    if n > 1400:
        rec(WARN, "handoff is an index",
            "%d words — a handoff this long is carrying content that belongs in an engagement "
            "or a session log. Cut it back to pointers." % n)
    else:
        rec(OK, "handoff is an index", "%d words" % n)




def check_untested_surface():
    """The number that makes an exhaustion claim falsifiable. Reported, never blocking."""
    import subprocess
    try:
        r = subprocess.run([sys.executable, os.path.join(OPS, "surface_report.py"), "--json"],
                           capture_output=True, text=True, timeout=120)
        import json as _j
        d = _j.loads(r.stdout)
        n = d.get("untested_on_approved", 0)
    except Exception:                                             # noqa: BLE001
        rec(WARN, "untested surface", "could not be counted — the check did NOT run")
        return
    if n > 0:
        rec(OK, "untested surface",
            "%d untested surface x class row(s) on APPROVED engagements — testable right now. "
            "'Exhausted' is not available as a general statement." % n)
    else:
        rec(OK, "untested surface", "no untested rows on any approved engagement")


def check_session_clock():
    """Runaway guard. Reports elapsed; never a reason to stop while surface remains."""
    import subprocess
    try:
        r = subprocess.run([sys.executable, os.path.join(OPS, "session_clock.py"), "check"],
                           capture_output=True, text=True, timeout=60)
        line = [l for l in r.stdout.splitlines() if "elapsed" in l]
        rec(OK, "session clock", line[0].split(":", 1)[1].strip() if line else "not stamped")
    except Exception:                                             # noqa: BLE001
        rec(WARN, "session clock", "unreadable")


def main():
    for fn in (check_required_files, check_no_dated_handoffs, check_handoff_freshness,
               check_actions_have_states, check_session_log_naming, check_handoff_is_an_index,
               check_untested_surface, check_session_clock):
        fn()

    print("=" * 78)
    print("  _OPS structure check")
    print("=" * 78)
    for level, name, detail in rows:
        print("[%s] %-24s %s" % (level, name, detail))
    n_warn = sum(1 for r in rows if r[0] == WARN)
    n_fail = sum(1 for r in rows if r[0] == FAIL)
    print("-" * 78)
    print("  %d ok · %d warn · %d fail" % (len(rows) - n_warn - n_fail, n_warn, n_fail))
    if n_fail:
        print("\n  A FAIL means the layer is structurally missing. Warnings are debt, never a")
        print("  reason to stop testing.")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
