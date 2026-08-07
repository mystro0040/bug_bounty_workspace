#!/usr/bin/env python3
"""How much permitted, untested surface remains — across EVERY engagement, counted, not asserted.

WHY THIS EXISTS

"Keep testing until there is genuinely nothing left" has been in the agent configuration for
weeks, escalated twice, and enforced by a hook. It still failed, repeatedly, in a way the hook
could not see:

    the hook fires on writing `state: DONE` to a _STATUS.md.
    the failure was never writing DONE. It was saying "this surface is exhausted" IN PROSE,
    to the operator, while the coverage ledger recorded hundreds of untested rows.

A claim made in conversation has no artifact, so no gate can catch it. The fix is not another
sentence addressed to a reader — that is what has already failed three times. The fix is a NUMBER
that is trivial to obtain, impossible to argue with, and that the agent is required to quote
before the word "exhausted" is allowed to mean anything.

WHAT IT COUNTS

Every `_COVERAGE.md` is a table of SURFACE x CLASS -> state. `untested` means exactly that: the
class was never exercised on that surface. This totals them, ranked, so "what is left" is a fact
rather than a recollection.

It deliberately does NOT judge value. A row being untested does not make it worth testing — a
walled host or a third-party platform is untested and should stay that way. Judgement stays with
the agent. What this removes is the ability to believe there is nothing left when there is.

USAGE
    python3 _OPS/surface_report.py             # ranked summary
    python3 _OPS/surface_report.py --detail <engagement-substring>
    python3 _OPS/surface_report.py --json
"""
import argparse
import collections
import json
import os
import re
import sys

OPS = os.path.dirname(os.path.abspath(__file__))
BUCKET = os.path.dirname(OPS)
ENGROOT = os.path.join(BUCKET, "engagements", "programs")

STATES = ("untested", "running", "clean", "finding", "blocked", "walled")
ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([a-z]+)\s*\|(.*)\|\s*$")


def read_coverage(path):
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = ROW.match(line.rstrip("\n"))
                if not m:
                    continue
                surface, cls, state, note = (m.group(1).strip(), m.group(2).strip(),
                                             m.group(3).strip().lower(), m.group(4).strip())
                if state not in STATES or surface.lower() == "surface":
                    continue
                rows.append({"surface": surface, "class": cls, "state": state, "note": note})
    except OSError:
        pass
    return rows


def collect():
    out = {}
    for base, dirs, files in os.walk(ENGROOT):
        if "_COVERAGE.md" in files:
            eng = os.path.relpath(base, os.path.dirname(ENGROOT))
            out[eng] = read_coverage(os.path.join(base, "_COVERAGE.md"))
    return out


def approved(eng):
    lock = os.path.join(BUCKET, "engagements", eng, ".scope_lock", "enforcement.json")
    try:
        return bool(json.load(open(lock, encoding="utf-8")).get("approved"))
    except Exception:                                              # noqa: BLE001
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--detail")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    data = collect()
    summary = []
    for eng, rows in sorted(data.items()):
        c = collections.Counter(r["state"] for r in rows)
        summary.append({"engagement": eng, "approved": approved(eng), "total": len(rows),
                        **{s: c.get(s, 0) for s in STATES}})

    if a.json:
        print(json.dumps({"engagements": summary,
                          "untested_total": sum(s["untested"] for s in summary),
                          "untested_on_approved": sum(s["untested"] for s in summary
                                                      if s["approved"])}, indent=1))
        return 0

    if a.detail:
        hits = [e for e in data if a.detail in e]
        for eng in hits:
            un = [r for r in data[eng] if r["state"] == "untested"]
            print("=" * 92)
            print("%s — %d untested row(s)" % (eng, len(un)))
            by_surface = collections.defaultdict(list)
            for r in un:
                by_surface[r["surface"]].append(r["class"])
            for surf, classes in sorted(by_surface.items()):
                print("  %-46s %s" % (surf[:46], ", ".join(sorted(classes))[:120]))
        return 0

    summary.sort(key=lambda s: (-s["untested"], s["engagement"]))
    tot_un = sum(s["untested"] for s in summary)
    tot_un_appr = sum(s["untested"] for s in summary if s["approved"])

    print("=" * 92)
    print("  UNTESTED SURFACE — counted from every _COVERAGE.md, not recalled")
    print("=" * 92)
    print("  %-52s %-9s %8s %7s %7s %7s" % ("engagement", "approved", "UNTESTED", "clean",
                                            "finding", "walled"))
    for s in summary:
        if s["total"] == 0:
            continue
        print("  %-52s %-9s %8d %7d %7d %7d"
              % (s["engagement"][:52], "yes" if s["approved"] else "-",
                 s["untested"], s["clean"], s["finding"], s["walled"]))

    print("-" * 92)
    print("  TOTAL untested rows                    : %d" % tot_un)
    print("  ...of which on APPROVED engagements    : %d   <-- testable right now" % tot_un_appr)
    print()
    if tot_un_appr > 0:
        print("  There is permitted, untested surface. The word \"exhausted\" is not available for")
        print("  the workspace as a whole. It may still be correct for ONE surface x class — say")
        print("  which, and say it with the row, never as a general statement.")
        print()
        print("  Drill in:  python3 _OPS/surface_report.py --detail <engagement-substring>")
    else:
        print("  No untested rows on any approved engagement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
