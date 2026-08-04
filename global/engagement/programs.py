#!/usr/bin/env python3
"""programs.py — what programs do we have, and what kind are they.

THE QUESTION THIS ANSWERS. "I'm looking for something to work on — which of these is registered
rather than public?" Registered and invite-only programs have far fewer researchers on them, so
the same effort finds more. That is a real prioritisation input and it was previously only
recoverable by opening program pages one at a time.

WHY A FIELD AND NOT A DIRECTORY. Engagements already nest by platform and bounty status
(`intigriti/bounty/...`). Adding visibility as a second directory axis would create a matrix, and
a program that graduates from application-only to public would have to MOVE — breaking its
scope-lock pointer, its findings paths, and its history. Visibility changes; a path should not.

WHAT IS STORED VERSUS DERIVED. Only the things that cannot be worked out from the path are
stored: visibility, currency, and where that claim came from. Platform and whether it pays are
derived from the directory, so they can never drift out of step with reality.

UNKNOWN IS A REAL ANSWER. Most captured program pages simply do not record visibility, so most
entries start as `unknown` rather than as a guess. A table of confident wrong answers is worse
than a table that admits what it does not know — especially for a field whose whole purpose is
deciding where to spend effort.

USAGE
    programs.py list                        table of every engagement
    programs.py list --visibility registered
    programs.py set <engagement> --visibility registered --currency EUR --source "program page"
"""
import argparse
import json
import os
import sys

BUCKET = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROGRAMS = os.path.join(BUCKET, "engagements", "programs")

VISIBILITIES = ["public", "registered", "application", "invite", "unknown"]

VISIBILITY_HELP = {
    "public": "anyone on the platform can see and test it. Most researchers, most duplicates.",
    "registered": "visible once your identity is verified. Far fewer researchers than public.",
    "application": "you apply and the program accepts you. Fewer still.",
    "invite": "invite-only. Fewest researchers, usually the best ratio of effort to result.",
    "unknown": "not recorded yet — check the program page and set it.",
}


def engagement_dirs():
    """Every engagement, as a path relative to engagements/."""
    found = []
    for platform in sorted(os.listdir(PROGRAMS)) if os.path.isdir(PROGRAMS) else []:
        pdir = os.path.join(PROGRAMS, platform)
        if not os.path.isdir(pdir):
            continue
        for pays in sorted(os.listdir(pdir)):
            bdir = os.path.join(pdir, pays)
            if not os.path.isdir(bdir):
                continue
            for prog in sorted(os.listdir(bdir)):
                full = os.path.join(bdir, prog)
                if os.path.isdir(full):
                    found.append((f"programs/{platform}/{pays}/{prog}", full))
    return found


def read_meta(full):
    facts_path = os.path.join(full, "facts.json")
    meta = {"visibility": "unknown", "currency": "?", "source": ""}
    if os.path.exists(facts_path):
        try:
            with open(facts_path) as fh:
                facts = json.load(fh)
            meta.update(facts.get("program_meta", {}))
        except (OSError, ValueError):
            meta["visibility"] = "unreadable"
    return meta


def read_state(full, width=34):
    """The state word from _STATUS.md, truncated.

    Several engagements have grown a parenthetical explanation onto the state line. That belongs
    in NOTES.md, but a listing must not become unreadable because of it, so it is trimmed here
    rather than reformatted in someone else's file.
    """
    path = os.path.join(full, "_STATUS.md")
    if not os.path.exists(path):
        return "-"
    try:
        for line in open(path):
            if line.strip().lower().startswith("state:"):
                state = line.split(":", 1)[1].split("#")[0].strip()
                return state if len(state) <= width else state[:width - 1] + "…"
    except OSError:
        pass
    return "-"


def approved(full):
    lock = os.path.join(full, ".scope_lock", "enforcement.json")
    if not os.path.exists(lock):
        return "no-scope"
    try:
        with open(lock) as fh:
            data = json.load(fh)
        return "approved" if data.get("approved") else "PENDING"
    except (OSError, ValueError):
        return "?"


def cmd_list(args):
    rows = []
    for rel, full in engagement_dirs():
        parts = rel.split("/")
        platform, pays = parts[1], parts[2]
        meta = read_meta(full)
        if args.visibility and meta["visibility"] != args.visibility:
            continue
        rows.append({
            "name": parts[3],
            "platform": platform,
            "pays": "yes" if pays == "bounty" else "no",
            "visibility": meta["visibility"],
            "currency": meta.get("currency", "?"),
            "scope": approved(full),
            "state": read_state(full),
        })

    if not rows:
        print("No engagements matched.")
        return 0

    w = {k: max(len(k), max(len(str(r[k])) for r in rows)) for k in rows[0]}
    header = "  ".join(k.upper().ljust(w[k]) for k in rows[0])
    print()
    print(header)
    print("-" * len(header))
    for r in sorted(rows, key=lambda r: (VISIBILITIES.index(r["visibility"])
                                         if r["visibility"] in VISIBILITIES else 99, r["name"])):
        print("  ".join(str(r[k]).ljust(w[k]) for k in r))

    unknown = sum(1 for r in rows if r["visibility"] == "unknown")
    print(f"\n{len(rows)} engagement(s).")
    if unknown:
        print(f"{unknown} with visibility still unknown — most captured program pages do not")
        print("record it. Set one with:  programs.py set <engagement> --visibility <kind>")
    print("\nVisibility, fewest researchers last:")
    for v in VISIBILITIES:
        print(f"  {v:11} {VISIBILITY_HELP[v]}")
    return 0


def cmd_set(args):
    target = args.engagement
    if not target.startswith("programs/"):
        target = "programs/" + target
    match = [(rel, full) for rel, full in engagement_dirs() if rel == target or rel.endswith("/" + target.split("/")[-1])]
    if not match:
        print(f"[!] no engagement matching {args.engagement!r}", file=sys.stderr)
        return 1
    if len(match) > 1:
        print(f"[!] ambiguous — matched {len(match)}:", file=sys.stderr)
        for rel, _ in match:
            print(f"      {rel}", file=sys.stderr)
        return 1

    rel, full = match[0]
    facts_path = os.path.join(full, "facts.json")
    if not os.path.exists(facts_path):
        print(f"[!] {rel} has no facts.json", file=sys.stderr)
        return 1

    with open(facts_path) as fh:
        facts = json.load(fh)

    meta = facts.get("program_meta", {})
    if args.visibility:
        meta["visibility"] = args.visibility
    if args.currency:
        meta["currency"] = args.currency
    if args.source:
        meta["source"] = args.source
    facts["program_meta"] = meta

    with open(facts_path, "w") as fh:
        json.dump(facts, fh, indent=2)
        fh.write("\n")

    print(f"[+] {rel}")
    for k, v in meta.items():
        print(f"      {k}: {v}")
    if meta.get("visibility") != "unknown" and not meta.get("source"):
        print("[i] No --source recorded. Worth adding where the claim came from, so a later")
        print("    reader can tell a checked fact from a guess.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="table of every engagement")
    lst.add_argument("--visibility", choices=VISIBILITIES, help="show only this kind")
    lst.set_defaults(func=cmd_list)

    st = sub.add_parser("set", help="record a program's visibility / currency")
    st.add_argument("engagement",
                    help="e.g. programs/<platform>/<bounty|no-bounty>/<slug>, or just the slug")
    st.add_argument("--visibility", choices=VISIBILITIES)
    st.add_argument("--currency")
    st.add_argument("--source", help="where the claim came from (program page, operator, ...)")
    st.set_defaults(func=cmd_set)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
