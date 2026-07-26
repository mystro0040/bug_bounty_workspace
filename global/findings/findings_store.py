#!/usr/bin/env python3
"""
findings_store — write-once storage for engagement findings.

A finding can represent hours of work and, on a paid program, real money. Everything else in
this framework is reproducible: recon can be re-run, scope can be recompiled, a scan repeats.
A finding cannot. It is the one artifact where an accidental overwrite is unrecoverable.

So findings are WRITE-ONCE, stored TWICE, and CHECKSUMMED:

    engagements/<eng>/findings/<id>-<slug>.md          primary
    engagements/<eng>/findings/.vault/<id>-<slug>.md   independent second copy
    engagements/<eng>/findings/INDEX.json              sha256 of both copies
    engagements/<eng>/findings/.journal.log            append-only, every event

FOUR INDEPENDENT PROTECTIONS, because any single one can be defeated by accident:

  1. REFUSE TO OVERWRITE. `new` will not write over an existing id. Revising a finding creates
     a NEW version (v2, v3, ...) and leaves the old one untouched. Nothing is ever replaced,
     so "I meant to edit and clobbered it" cannot happen.
  2. TWO COPIES. Primary and vault are written separately and hashed separately. A truncating
     write, a bad editor save, or a botched sync hits one, not both.
  3. READ-ONLY (0444). A finding is chmod'd read-only after writing, so a careless `>` or a
     script writing to the wrong path fails loudly instead of silently succeeding.
  4. APPEND-ONLY JOURNAL. Every create, amend and verify is logged with hashes. Even if both
     copies were destroyed, the journal proves the finding existed, when, and with what content
     hash — which is what a program needs to honour a disclosure timestamp.

`verify` re-hashes both copies against INDEX.json and reports drift, truncation, or absence.
Run it before any bulk operation on an engagement directory.

Deliberately NOT relying on: git (a finding must survive before it is committed), the S3 sync
(mirrors deletions by design), or filesystem snapshots (not present on every machine).

Usage — interactive by default:
    python3 findings_store.py                     menu
    python3 findings_store.py new                 guided capture
    python3 findings_store.py list
    python3 findings_store.py verify              integrity check on every finding
    python3 findings_store.py show <id>
    python3 findings_store.py amend <id>          adds a NEW version, never edits in place
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys

BUCKET = os.path.expanduser("~/Workspace/buckets/bug-bounty-workspace-bucket")
ENGAGEMENTS = os.path.join(BUCKET, "engagements")
ACTIVE_FILE = os.path.join(BUCKET, ".claude", "state", "active_engagement")

FINDING_FILE = re.compile(r"^F\d+-.*\.md$")   # what verify() treats as a finding

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
STATUSES = ["draft", "confirmed", "reported", "triaged", "accepted", "duplicate", "rejected"]


class FindingsError(RuntimeError):
    pass


# --------------------------------------------------------------------------- helpers
def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def active_engagement():
    if os.path.isfile(ACTIVE_FILE):
        with open(ACTIVE_FILE, encoding="utf-8") as fh:
            name = fh.read().strip()
        if name:
            return name
    raise FindingsError(
        f"no active engagement set ({ACTIVE_FILE} is missing or empty). "
        f"Set one, or pass --engagement.")


def paths(engagement):
    root = os.path.join(ENGAGEMENTS, engagement, "findings")
    return {
        "root": root,
        "vault": os.path.join(root, ".vault"),
        "index": os.path.join(root, "INDEX.json"),
        "journal": os.path.join(root, ".journal.log"),
    }


def _slug(text, limit=48):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:limit].rstrip("-")) or "finding"


def _journal(p, event, **fields):
    """Append-only. Never rewritten, never truncated — opened 'a' every time on purpose."""
    os.makedirs(p["root"], exist_ok=True)
    rec = {"ts": _now(), "event": event}
    rec.update(fields)
    with open(p["journal"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def load_index(p):
    if not os.path.isfile(p["index"]):
        return {"findings": []}
    try:
        with open(p["index"], encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        # Never silently start from scratch — that is how an index gets replaced by an empty one.
        raise FindingsError(
            f"{p['index']} is unreadable ({exc}). Refusing to continue: writing a fresh index "
            f"here would erase the record of every finding already stored. Repair or move it "
            f"aside manually, then re-run `verify`.")


def save_index(p, idx):
    os.makedirs(p["root"], exist_ok=True)
    tmp = p["index"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, indent=2, sort_keys=True)
    os.replace(tmp, p["index"])


def _write_protected(path, body):
    """Write once, then drop write permission. Refuses if the file already exists."""
    if os.path.exists(path):
        raise FindingsError(f"{path} already exists — refusing to overwrite a stored finding.")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)   # 0444
    return _sha256(path)


def next_id(p):
    idx = load_index(p)
    n = 0
    for f in idx["findings"]:
        m = re.match(r"F(\d+)", f.get("id", ""))
        if m:
            n = max(n, int(m.group(1)))
    return f"F{n + 1:03d}"


# --------------------------------------------------------------------------- core
def record(engagement, title, severity, asset, body, status="draft", version=1, parent=None):
    """Store a finding in both locations and index it. Never overwrites."""
    if severity not in SEVERITIES:
        raise FindingsError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    if not (title or "").strip():
        raise FindingsError("a finding needs a title")
    p = paths(engagement)
    os.makedirs(p["vault"], exist_ok=True)

    fid = parent or next_id(p)
    suffix = "" if version == 1 else f".v{version}"
    name = f"{fid}-{_slug(title)}{suffix}.md"

    doc = (f"# {fid}{suffix} — {title}\n\n"
           f"- **Engagement:** {engagement}\n"
           f"- **Severity:** {severity}\n"
           f"- **Asset:** {asset or '(unspecified)'}\n"
           f"- **Status:** {status}\n"
           f"- **Recorded:** {_now()}\n"
           f"- **Version:** {version}\n\n"
           f"---\n\n{body.rstrip()}\n")

    primary = os.path.join(p["root"], name)
    vault = os.path.join(p["vault"], name)
    h1 = _write_protected(primary, doc)
    try:
        h2 = _write_protected(vault, doc)
    except FindingsError:
        # Primary landed, vault did not. Say so loudly — a single-copy finding is exactly the
        # state this module exists to avoid, and silently continuing would hide it.
        _journal(p, "vault_write_failed", id=fid, file=name, primary_sha256=h1)
        raise FindingsError(
            f"stored the primary copy at {primary} but could NOT write the vault copy at "
            f"{vault}. The finding exists but is UNPROTECTED. Resolve the vault path and "
            f"re-run `verify`.")
    if h1 != h2:
        raise FindingsError(f"the two copies of {name} hashed differently ({h1} vs {h2}) — "
                            f"do not trust either until this is understood.")

    idx = load_index(p)
    idx["findings"].append({
        "id": fid, "version": version, "title": title, "severity": severity,
        "asset": asset or "", "status": status, "file": name,
        "sha256": h1, "recorded": _now(),
    })
    save_index(p, idx)
    _journal(p, "recorded", id=fid, version=version, file=name, sha256=h1,
             severity=severity, title=title)
    return {"id": fid, "version": version, "file": name, "sha256": h1,
            "primary": primary, "vault": vault}


def amend(engagement, fid, body, title=None, severity=None, asset=None, status=None):
    """Add a NEW version. The previous version is never touched."""
    p = paths(engagement)
    idx = load_index(p)
    prior = [f for f in idx["findings"] if f["id"] == fid]
    if not prior:
        raise FindingsError(f"no finding {fid} in {p['index']}")
    latest = max(prior, key=lambda f: f.get("version", 1))
    return record(engagement,
                  title or latest["title"], severity or latest["severity"],
                  asset if asset is not None else latest.get("asset", ""),
                  body, status or latest.get("status", "draft"),
                  version=latest.get("version", 1) + 1, parent=fid)


def verify(engagement):
    """Re-hash both copies of every indexed finding. Reports rather than repairs."""
    p = paths(engagement)
    idx = load_index(p)
    report = {"engagement": engagement, "checked": 0, "ok": 0, "problems": []}

    for f in idx["findings"]:
        report["checked"] += 1
        primary = os.path.join(p["root"], f["file"])
        vault = os.path.join(p["vault"], f["file"])
        issues = []
        for label, path in (("primary", primary), ("vault", vault)):
            if not os.path.isfile(path):
                issues.append(f"{label} MISSING at {path}")
                continue
            got = _sha256(path)
            if got != f["sha256"]:
                issues.append(f"{label} CHANGED (index {f['sha256'][:12]}… "
                              f"on disk {got[:12]}…) at {path}")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                issues.append(f"{label} is WRITABLE ({oct(mode)}) — overwrite protection is off")
        if issues:
            report["problems"].append({"id": f["id"], "file": f["file"], "issues": issues})
        else:
            report["ok"] += 1

    # A finding on disk that the index does not know about is as bad as a missing one.
    #
    # Matched on the FINDING NAME PATTERN, not merely ".md": the findings directory also holds
    # scaffolding (README.md, templates), and flagging those made the first run report a problem
    # that was not one. A check that cries wolf gets ignored, and then the real warning goes with
    # it — so this only looks at files that claim to be findings.
    known = {f["file"] for f in idx["findings"]}
    if os.path.isdir(p["root"]):
        for name in sorted(os.listdir(p["root"])):
            if FINDING_FILE.match(name) and name not in known:
                report["problems"].append(
                    {"id": "?", "file": name,
                     "issues": [f"UNINDEXED finding present at {os.path.join(p['root'], name)} — "
                                f"it exists but nothing is protecting or tracking it"]})
    _journal(p, "verified", checked=report["checked"], ok=report["ok"],
             problems=len(report["problems"]))
    return report


def restore(engagement, fid):
    """Copy the vault copy back over a damaged/missing primary. The only write-back path."""
    p = paths(engagement)
    idx = load_index(p)
    entries = [f for f in idx["findings"] if f["id"] == fid]
    if not entries:
        raise FindingsError(f"no finding {fid}")
    restored = []
    for f in entries:
        vault = os.path.join(p["vault"], f["file"])
        primary = os.path.join(p["root"], f["file"])
        if not os.path.isfile(vault):
            raise FindingsError(f"vault copy missing for {f['file']} — nothing to restore from")
        if _sha256(vault) != f["sha256"]:
            raise FindingsError(f"the vault copy of {f['file']} does not match the index either. "
                                f"Both copies are suspect; inspect {p['journal']} before acting.")
        if os.path.exists(primary):
            os.chmod(primary, stat.S_IRUSR | stat.S_IWUSR)
            os.unlink(primary)
        shutil.copy2(vault, primary)
        os.chmod(primary, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        restored.append(f["file"])
        _journal(p, "restored", id=fid, file=f["file"], sha256=f["sha256"])
    return restored


def listing(engagement):
    return load_index(paths(engagement))["findings"]


# --------------------------------------------------------------------------- cross-engagement index
# Where the roll-up index is written. Findings themselves NEVER move — this is a pointer file
# so you can see everything at a glance instead of walking every engagement directory.
#
# PRIVATE DESTINATIONS ONLY. The index names engagements, and at least one is an NDA program;
# listing it publicly would disclose participation. The execution layer is routinely propagated
# to a PUBLIC repo copy, so "just put it next to the other synced files" is exactly how this
# would leak. _assert_private() below is the mechanism that stops it.
INDEX_DESTINATIONS = [
    os.path.expanduser("~/Workspace/buckets/bug-bounty-workspace-bucket"),
    os.path.expanduser("~/Workspace/Production_Ready/private/Offensive_Operations/bug_bounty_workspace"),
]
INDEX_FILENAME = "FINDINGS.md"

# A path segment that means "this tree is published". Deliberately crude and deliberately
# over-broad: a false refusal costs a moment, a false permit is permanent.
_PUBLIC_MARKERS = ("/public/", "/Offensive_Security/", "/docs/", "/www/")


def _assert_private(root):
    """Refuse to write the roll-up anywhere that looks published."""
    real = os.path.realpath(root) + "/"
    for marker in _PUBLIC_MARKERS:
        if marker in real:
            raise FindingsError(
                f"refusing to write {INDEX_FILENAME} to {root}: the path contains {marker!r}, "
                f"which marks a published tree. This index names engagements — including NDA "
                f"programs — and must never be committed to a public repository.")
    return real


def discover(engagements_root=None):
    """Find every engagement that has recorded findings. Returns [(engagement, [findings])]."""
    root = engagements_root or ENGAGEMENTS
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != "findings" or "INDEX.json" not in filenames:
            continue
        dirnames[:] = []                                   # do not descend into .vault
        eng = os.path.relpath(os.path.dirname(dirpath), root)
        try:
            items = load_index(paths(eng))["findings"]
        except FindingsError:
            items = None                                   # damaged index: surface, never skip
        out.append((eng, items))
    return sorted(out, key=lambda x: x[0])


_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def build_index(engagements_root=None):
    """Render the roll-up as markdown. Pure function of what is on disk."""
    found = discover(engagements_root)
    root = engagements_root or ENGAGEMENTS
    rows, damaged, total = [], [], 0
    for eng, items in found:
        if items is None:
            damaged.append(eng)
            continue
        for f in items:
            total += 1
            rows.append((f.get("severity", "informational"), eng, f))
    rows.sort(key=lambda r: (_SEV_ORDER.get(r[0], 99), r[1], r[2].get("id", "")))

    L = []
    L.append("# Findings — index")
    L.append("")
    L.append("**Generated file — do not edit by hand.** Regenerate with:")
    L.append("")
    L.append("```")
    L.append("python3 <framework>/utilities/findings/findings_store.py index")
    L.append("```")
    L.append("")
    L.append("A pointer only. Findings live in their own engagement directories and are not "
             "moved or copied here — this exists so you can see everything without walking "
             "every engagement.")
    L.append("")
    L.append("Every finding is stored twice (primary + `.vault/`), read-only, hash-indexed. "
             "Check integrity with `findings_store.py verify --engagement <name>`.")
    L.append("")
    L.append(f"**{total} finding(s) across {len([e for e, i in found if i])} engagement(s).**")
    L.append("")

    if damaged:
        L.append("## ⛔ DAMAGED INDEXES — resolve before trusting this file")
        L.append("")
        for eng in damaged:
            L.append(f"- `{eng}` — findings/INDEX.json is unreadable; findings may exist "
                     f"that are not listed below.")
        L.append("")

    if rows:
        L.append("## All findings, most severe first")
        L.append("")
        L.append("| Sev | Status | Engagement | ID | Title | File |")
        L.append("|---|---|---|---|---|---|")
        for sev, eng, f in rows:
            path = os.path.join(root, eng, "findings", f["file"])
            title = f.get("title", "").replace("|", "\\|")
            L.append(f"| {sev} | {f.get('status','')} | `{eng}` | {f.get('id','')} | "
                     f"{title} | `{path}` |")
        L.append("")

    L.append("## By engagement")
    L.append("")
    for eng, items in found:
        d = os.path.join(root, eng, "findings")
        if items is None:
            L.append(f"### `{eng}`\n\n- ⛔ index unreadable — inspect `{d}` directly\n")
            continue
        L.append(f"### `{eng}`")
        L.append("")
        L.append(f"- directory: `{d}`")
        L.append(f"- backup copies: `{os.path.join(d, '.vault')}`")
        L.append(f"- journal: `{os.path.join(d, '.journal.log')}` (append-only)")
        L.append("")
        for f in sorted(items, key=lambda x: (_SEV_ORDER.get(x.get("severity"), 99),
                                              x.get("id", ""))):
            v = "" if f.get("version", 1) == 1 else f" (v{f['version']})"
            L.append(f"  - **{f.get('id','')}{v}** · {f.get('severity','')} · "
                     f"{f.get('status','')} — {f.get('title','')}")
            L.append(f"    `{os.path.join(d, f['file'])}`")
        L.append("")
    return "\n".join(L) + "\n"


def write_index(destinations=None, engagements_root=None):
    """Write the roll-up to each private destination. Returns the paths written."""
    body = build_index(engagements_root)
    written = []
    for root in (destinations or INDEX_DESTINATIONS):
        if not os.path.isdir(root):
            continue
        _assert_private(root)                              # refuses published trees
        dest = os.path.join(root, INDEX_FILENAME)
        # Regenerated in place: this file is derived, so overwriting is correct here. The
        # findings it points at remain write-once — nothing under findings/ is touched.
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(body)
        written.append(dest)
    return written


# --------------------------------------------------------------------------- CLI
def _ask(prompt, default=None, allowed=None):
    while True:
        d = f" [{default}]" if default else ""
        val = input(f"{prompt}{d}: ").strip()
        if not val and default:
            val = default
        if not val:
            print("  (required)")
            continue
        if allowed and val not in allowed:
            print(f"  must be one of: {', '.join(allowed)}")
            continue
        return val


def _multiline(prompt):
    print(f"{prompt} (finish with a single '.' on its own line)")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == ".":
            break
        lines.append(line)
    return "\n".join(lines)


def _editor_body():
    """Offer $EDITOR for the write-up; fall back to inline entry."""
    ed = os.environ.get("EDITOR")
    if not ed:
        return _multiline("Write-up")
    use = input(f"Use {ed} for the write-up? [Y/n]: ").strip().lower()
    if use in ("n", "no"):
        return _multiline("Write-up")
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".md", prefix="finding-")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("## Summary\n\n\n## Steps to reproduce\n\n1. \n\n## Impact\n\n\n"
                 "## Evidence\n\n\n## Remediation\n\n")
    subprocess.call([ed, tmp])
    with open(tmp, encoding="utf-8") as fh:
        body = fh.read()
    os.unlink(tmp)
    return body


def cmd_new(eng):
    print(f"\nNew finding — engagement: {eng}\n")
    title = _ask("Title")
    severity = _ask(f"Severity ({'/'.join(SEVERITIES)})", "medium", SEVERITIES)
    asset = _ask("Affected asset (host/URL)", "(unspecified)")
    status = _ask(f"Status ({'/'.join(STATUSES)})", "draft", STATUSES)
    body = _editor_body()
    if not body.strip():
        print("Empty write-up — aborted, nothing written.")
        return 1
    res = record(eng, title, severity, asset, body, status)
    print(f"\n  stored   {res['id']}  {res['file']}")
    print(f"  primary  {res['primary']}")
    print(f"  vault    {res['vault']}")
    print(f"  sha256   {res['sha256'][:16]}…")
    print("  both copies are read-only (0444); `amend` adds a version, it never overwrites.")
    return 0


def cmd_list(eng):
    items = listing(eng)
    if not items:
        print(f"no findings recorded for {eng}")
        return 0
    print(f"\n{len(items)} finding(s) — {eng}\n")
    for f in items:
        v = "" if f.get("version", 1) == 1 else f" v{f['version']}"
        print(f"  {f['id']}{v:4} {f['severity']:14} {f['status']:10} {f['title'][:48]}")
        print(f"        {f.get('asset','')}")
    return 0


def cmd_verify(eng):
    r = verify(eng)
    print(f"\nintegrity — {eng}")
    print(f"  checked {r['checked']}, intact {r['ok']}, problems {len(r['problems'])}")
    for p_ in r["problems"]:
        print(f"\n  ⛔ {p_['id']}  {p_['file']}")
        for i in p_["issues"]:
            print(f"     {i}")
    if not r["problems"]:
        print("  ✓ every finding present in both copies, hashes match, all read-only")
    return 1 if r["problems"] else 0


def cmd_show(eng, fid):
    p = paths(eng)
    hits = [f for f in load_index(p)["findings"] if f["id"] == fid]
    if not hits:
        print(f"no finding {fid}")
        return 1
    for f in sorted(hits, key=lambda x: x.get("version", 1)):
        path = os.path.join(p["root"], f["file"])
        print(f"\n===== {f['file']} =====")
        if os.path.isfile(path):
            print(open(path, encoding="utf-8").read())
        else:
            print(f"(primary missing — vault copy at {os.path.join(p['vault'], f['file'])})")
    return 0


def menu(eng):
    while True:
        print(f"\n=== Findings — {eng} ===")
        print("  1) New finding")
        print("  2) List findings")
        print("  3) Verify integrity (both copies + hashes)")
        print("  4) Show a finding")
        print("  5) Amend a finding (adds a version, never overwrites)")
        print("  7) Regenerate the cross-engagement findings index")
        print("  6) Restore a damaged finding from the vault")
        print("  q) Quit")
        c = input("\nChoice: ").strip().lower()
        try:
            if c == "1":
                cmd_new(eng)
            elif c == "2":
                cmd_list(eng)
            elif c == "3":
                cmd_verify(eng)
            elif c == "4":
                cmd_show(eng, _ask("Finding id (e.g. F001)"))
            elif c == "5":
                fid = _ask("Finding id to amend")
                body = _editor_body()
                r = amend(eng, fid, body)
                print(f"  added {r['file']} — the previous version is untouched")
            elif c == "7":
                for p_ in write_index():
                    print(f"  wrote {p_}")
            elif c == "6":
                fid = _ask("Finding id to restore")
                print("  restored:", ", ".join(restore(eng, fid)))
            elif c in ("q", "quit", "exit"):
                return 0
            else:
                print("  ?")
        except FindingsError as exc:
            print(f"\n  ERROR: {exc}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write-once storage for engagement findings.")
    ap.add_argument("action", nargs="?",
                    choices=["new", "list", "verify", "show", "amend", "restore", "index"])
    ap.add_argument("id", nargs="?")
    ap.add_argument("--engagement")
    ap.add_argument("--title")
    ap.add_argument("--severity", choices=SEVERITIES)
    ap.add_argument("--asset")
    ap.add_argument("--status", choices=STATUSES, default="draft")
    ap.add_argument("--body", help="write-up text, or '-' to read stdin")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    try:
        eng = a.engagement or active_engagement()
        if a.action is None:
            return menu(eng)
        if a.action == "new":
            if a.title and a.body:                      # non-interactive path for automation
                body = sys.stdin.read() if a.body == "-" else a.body
                res = record(eng, a.title, a.severity or "medium", a.asset or "", body, a.status)
                print(json.dumps(res, indent=2) if a.json else
                      f"stored {res['id']} -> {res['file']} ({res['sha256'][:16]}…)")
                return 0
            return cmd_new(eng)
        if a.action == "list":
            if a.json:
                print(json.dumps(listing(eng), indent=2))
                return 0
            return cmd_list(eng)
        if a.action == "verify":
            if a.json:
                r = verify(eng)
                print(json.dumps(r, indent=2))
                return 1 if r["problems"] else 0
            return cmd_verify(eng)
        if a.action == "show":
            return cmd_show(eng, a.id or _ask("Finding id"))
        if a.action == "amend":
            body = sys.stdin.read() if a.body == "-" else (a.body or _editor_body())
            r = amend(eng, a.id or _ask("Finding id"), body, a.title, a.severity,
                      a.asset, a.status)
            print(f"added {r['file']} — previous version untouched")
            return 0
        if a.action == "index":
            paths_written = write_index()
            if a.json:
                print(json.dumps({"written": paths_written}, indent=2))
            else:
                print(f"findings index regenerated ({len(paths_written)} destination(s)):")
                for p_ in paths_written:
                    print(f"  {p_}")
                if not paths_written:
                    print("  (no private destination found — nothing written)")
            return 0
        if a.action == "restore":
            print("restored:", ", ".join(restore(eng, a.id or _ask("Finding id"))))
            return 0
    except FindingsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
