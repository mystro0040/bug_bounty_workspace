#!/usr/bin/env python3
"""lessons.py — the learning loop. What we worked out, with the evidence, and a way back out.

THE PROBLEM. The operator gives the same correction repeatedly and it does not stick. Not because
nobody wrote it down — several of these corrections ARE written down as memories — but because a
memory arrives as background context and loses to in-the-moment caution. Meanwhile the obvious fix,
"put it in the config", is how a config becomes a thousand lines nobody reads, and how one offhand
remark on a bad day becomes a permanent rule.

So this is a LADDER with a way back DOWN, not a pile.

    observed        seen once. Recorded, and that is all. Changes nothing about how anyone works.
    candidate       seen at least twice, or stated as a rule. Now worth acting on.
    active          load-bearing. Belongs in the operating context where it is an INSTRUCTION
                    rather than a hint. Promotion to that file is STAGED for the operator, never
                    self-applied.
    retired         turned out to be wrong, or stopped being true. Kept, with the reason.

EVIDENCE IS THE POINT. Every lesson carries the specific occasions that produced it — what
happened, what the correction was. A rule you can trace to three real events is one you can judge,
argue with, and retract. A rule with no evidence is folklore, and folklore is what makes a
framework rigid.

SCOPE, AND WHY IT CAN CHANGE. Each lesson is `engagement`, `platform`, or `general`. The operator's
worry was getting locked into a bad loop — a lesson learned from one situation quietly governing
every situation. So scope is a field, not a location, and `rescope` moves it in either direction.
Something learned on one bank engagement can be narrowed back down when it turns out not to
generalise, without losing the record that it was once believed.

NOTHING HERE BLOCKS WORK. There is no gate, no check that must pass, no prompt. It is a notebook
with a promotion rule. If it ever slows anyone down, it has failed.

USAGE
    lessons.py add "<one line>" --scope general --why "..." --evidence "what happened"
    lessons.py evidence <name> "another occurrence"      # this is what promotes it
    lessons.py list [--scope X] [--status Y]
    lessons.py review                                    # what is ready to move, what looks stale
    lessons.py rescope <name> --to platform
    lessons.py retire <name> --because "..."
"""
import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUCKET = os.path.dirname(os.path.dirname(HERE))
STORE = os.path.join(HERE, "lessons")
NEEDS_REVIEW = os.path.join(BUCKET, "_NEEDS-REVIEW")

SCOPES = ["engagement", "platform", "general"]
STATUSES = ["observed", "candidate", "active", "retired"]

#: Occurrences needed before a lesson stops being an anecdote. Two, not one, precisely because the
#: operator asked not to have their every passing remark become a permanent rule — and not more
#: than two, because a correction given twice is already costing time.
PROMOTE_AT = 2


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return "-".join(s.split("-")[:8])[:60] or "lesson"


def today():
    return datetime.date.today().isoformat()


def path_for(name):
    return os.path.join(STORE, name + ".md")


def load(name):
    path = path_for(name)
    if not os.path.exists(path):
        return None
    text = open(path, encoding="utf-8").read()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        return None
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    try:
        meta["evidence"] = json.loads(meta.get("evidence", "[]"))
    except ValueError:
        meta["evidence"] = []
    return {"meta": meta, "body": m.group(2), "name": name}


def save(name, meta, body):
    os.makedirs(STORE, exist_ok=True)
    meta = dict(meta)
    meta["evidence"] = json.dumps(meta.get("evidence", []))
    front = "\n".join(f"{k}: {v}" for k, v in meta.items())
    with open(path_for(name), "w", encoding="utf-8") as fh:
        fh.write(f"---\n{front}\n---\n{body}")


def all_lessons():
    if not os.path.isdir(STORE):
        return []
    out = []
    for fn in sorted(os.listdir(STORE)):
        if fn.endswith(".md"):
            rec = load(fn[:-3])
            if rec:
                out.append(rec)
    return out


def cmd_add(args):
    name = args.name or slug(args.lesson)
    if os.path.exists(path_for(name)):
        print(f"[!] {name} already exists. Add an occurrence instead:")
        print(f"      lessons.py evidence {name} \"what happened this time\"")
        return 1

    evidence = [{"date": today(), "what": args.evidence}] if args.evidence else []
    meta = {
        "name": name,
        "scope": args.scope,
        "status": "candidate" if args.rule else "observed",
        "created": today(),
        "updated": today(),
        "evidence": evidence,
    }
    body = f"{args.lesson}\n\n"
    if args.why:
        body += f"**Why:** {args.why}\n\n"
    if args.how:
        body += f"**How to apply:** {args.how}\n\n"
    save(name, meta, body)

    print(f"[+] {name}  ({meta['status']}, {args.scope})")
    if meta["status"] == "observed":
        print(f"[i] Recorded only — one occurrence changes nothing. It becomes a candidate at "
              f"{PROMOTE_AT}:")
        print(f"      lessons.py evidence {name} \"what happened\"")
    return 0


def cmd_evidence(args):
    rec = load(args.name)
    if not rec:
        print(f"[!] no lesson named {args.name!r}", file=sys.stderr)
        return 1
    meta = rec["meta"]
    ev = meta.get("evidence", [])
    ev.append({"date": today(), "what": args.what})
    meta["evidence"] = ev
    meta["updated"] = today()

    was = meta.get("status")
    if was == "observed" and len(ev) >= PROMOTE_AT:
        meta["status"] = "candidate"
    save(args.name, meta, rec["body"])

    print(f"[+] {args.name}: {len(ev)} occurrence(s)")
    if was == "observed" and meta["status"] == "candidate":
        print("[!] PROMOTED to candidate — this has now happened more than once, so it is a "
              "pattern rather than an anecdote. Act on it.")
    return 0


def cmd_list(args):
    rows = all_lessons()
    if args.scope:
        rows = [r for r in rows if r["meta"].get("scope") == args.scope]
    if args.status:
        rows = [r for r in rows if r["meta"].get("status") == args.status]
    elif not args.all:
        rows = [r for r in rows if r["meta"].get("status") != "retired"]

    if not rows:
        print("No lessons recorded yet." if not args.status else "Nothing matched.")
        return 0

    print()
    for r in sorted(rows, key=lambda r: (STATUSES.index(r["meta"].get("status", "observed")),
                                         r["name"])):
        m = r["meta"]
        first = r["body"].strip().splitlines()[0] if r["body"].strip() else ""
        n = len(m.get("evidence", []))
        print(f"  [{m.get('status','?'):9}] [{m.get('scope','?'):10}] {r['name']}  ({n}x)")
        print(f"              {first[:96]}")
    print(f"\n{len(rows)} lesson(s).")
    return 0


def cmd_review(args):
    rows = all_lessons()
    ready = [r for r in rows if r["meta"].get("status") == "candidate"]
    thin = [r for r in rows if r["meta"].get("status") == "observed"]
    active = [r for r in rows if r["meta"].get("status") == "active"]

    print("\n=== ready to act on (a repeated pattern, or stated outright as a rule) ===")
    for r in ready:
        m = r["meta"]
        print(f"  {r['name']}  ({len(m.get('evidence', []))}x, {m.get('scope')})")
        for e in m.get("evidence", [])[-3:]:
            print(f"      {e.get('date')}  {str(e.get('what'))[:88]}")
    if not ready:
        print("  (none)")

    print("\n=== single occurrence — deliberately not acted on yet ===")
    for r in thin:
        print(f"  {r['name']}  ({r['meta'].get('scope')})")
    if not thin:
        print("  (none)")

    print("\n=== active: these are instructions, so they deserve doubt ===")
    for r in active:
        print(f"  {r['name']}  ({r['meta'].get('scope')})")
    if not active:
        print("  (none)")

    print("\nIf an active lesson has stopped being true, retire it — a stale instruction that")
    print("everyone still follows costs more than one nobody wrote down.")
    print("  lessons.py retire <name> --because \"...\"")
    return 0


def cmd_rescope(args):
    rec = load(args.name)
    if not rec:
        print(f"[!] no lesson named {args.name!r}", file=sys.stderr)
        return 1
    old = rec["meta"].get("scope")
    rec["meta"]["scope"] = args.to
    rec["meta"]["updated"] = today()
    body = rec["body"]
    if args.because:
        body += f"\n**Rescoped {today()}** ({old} -> {args.to}): {args.because}\n"
    save(args.name, rec["meta"], body)
    print(f"[+] {args.name}: {old} -> {args.to}")
    if SCOPES.index(args.to) < SCOPES.index(old or "general"):
        print("[i] Narrowed. That is the loop working — a lesson that did not generalise is")
        print("    supposed to be narrowed rather than quietly obeyed everywhere.")
    return 0


def cmd_retire(args):
    rec = load(args.name)
    if not rec:
        print(f"[!] no lesson named {args.name!r}", file=sys.stderr)
        return 1
    rec["meta"]["status"] = "retired"
    rec["meta"]["updated"] = today()
    body = rec["body"] + f"\n**RETIRED {today()}:** {args.because}\n"
    save(args.name, rec["meta"], body)
    print(f"[+] {args.name} retired.")
    print("[i] Kept rather than deleted. A retired lesson with its reason stops the next agent")
    print("    re-deriving the same wrong answer from the same plausible reasoning.")
    return 0


def cmd_stage(args):
    """Stage a promotion to the operating context. Deliberately does NOT apply it."""
    rec = load(args.name)
    if not rec:
        print(f"[!] no lesson named {args.name!r}", file=sys.stderr)
        return 1
    if rec["meta"].get("status") != "candidate":
        print(f"[!] {args.name} is '{rec['meta'].get('status')}', not 'candidate'. Only a lesson")
        print("    seen more than once is worth making an instruction.")
        return 1

    os.makedirs(NEEDS_REVIEW, exist_ok=True)
    existing = [f for f in os.listdir(NEEDS_REVIEW) if re.match(r"^\d\d_", f)]
    num = f"{len(existing) + 1:02d}"
    out = os.path.join(NEEDS_REVIEW, f"{num}_promote-{args.name}.md")

    ev = rec["meta"].get("evidence", [])
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(f"# Promote a lesson into the operating context: {args.name}\n\n")
        fh.write("## What it says\n\n" + rec["body"].strip() + "\n\n")
        fh.write(f"## Why it is being proposed ({len(ev)} occurrences)\n\n")
        for e in ev:
            fh.write(f"* {e.get('date')} — {e.get('what')}\n")
        fh.write("\n## What a yes changes\n\n")
        fh.write(f"It moves from a recorded lesson to an INSTRUCTION in the operating context, "
                 f"scoped `{rec['meta'].get('scope')}`. Agents would follow it without being "
                 f"reminded.\n\n")
        fh.write("## What a no changes\n\nNothing. It stays a candidate and keeps accumulating "
                 "evidence, or gets retired if it was wrong.\n\n")
        fh.write("## Recommendation\n\nOperator's call. The evidence above is the whole argument; "
                 "if it does not read as a pattern to you, it is not one.\n")

    print(f"[+] staged: {os.path.relpath(out, BUCKET)}")
    print("[i] NOT applied. Promoting a lesson to an instruction changes how every future session")
    print("    behaves, so it is the operator's decision, not an agent's.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="record something learned")
    a.add_argument("lesson")
    a.add_argument("--name")
    a.add_argument("--scope", choices=SCOPES, default="general")
    a.add_argument("--why", help="why it is true — the part that makes it judgeable")
    a.add_argument("--how", help="how to apply it concretely")
    a.add_argument("--evidence", help="what happened this time")
    a.add_argument("--rule", action="store_true",
                   help="the operator stated it as a rule — starts as a candidate, not an anecdote")
    a.set_defaults(func=cmd_add)

    e = sub.add_parser("evidence", help="record another occurrence (this is what promotes)")
    e.add_argument("name")
    e.add_argument("what")
    e.set_defaults(func=cmd_evidence)

    l = sub.add_parser("list", help="show lessons")
    l.add_argument("--scope", choices=SCOPES)
    l.add_argument("--status", choices=STATUSES)
    l.add_argument("--all", action="store_true", help="include retired")
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("review", help="what is ready to act on, and what deserves doubt")
    r.set_defaults(func=cmd_review)

    rs = sub.add_parser("rescope", help="widen or NARROW a lesson's reach")
    rs.add_argument("name")
    rs.add_argument("--to", choices=SCOPES, required=True)
    rs.add_argument("--because")
    rs.set_defaults(func=cmd_rescope)

    rt = sub.add_parser("retire", help="it was wrong, or stopped being true")
    rt.add_argument("name")
    rt.add_argument("--because", required=True)
    rt.set_defaults(func=cmd_retire)

    st = sub.add_parser("stage", help="propose promotion to the operating context (operator decides)")
    st.add_argument("name")
    st.set_defaults(func=cmd_stage)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
