#!/usr/bin/env python3
"""sync_workspace.py — put the FRAMEWORK on a remote host, deliberately leaving the data behind.

WHY THIS IS SELECTIVE AND NOT AN rsync
--------------------------------------
The bucket is 315 MB. 3.3 MB of that is the framework — the scope wall, CLAUDE.md, the operating
modes, the skills, and each engagement's scope + compiled TTP lock. The other 311 MB is
target-derived: recon output, captured responses, host inventories, evidence.

`global/CLAUDE.md` §2F-NET is explicit that the second category does not belong on a rented box:

    "Engagement data does NOT live on the executor. The box is a transient workspace, never
     storage. Target responses and host inventories are engagement material; leaving them on a
     rented VPS is a disclosure the program never agreed to."

So this tool ships what a session needs to work CORRECTLY — context and boundaries — and refuses to
ship what a program never agreed to have stored elsewhere. A blanket sync would quietly retire that
rule, which is not a decision a sync script gets to make.

THE POINT THAT MATTERS MOST
---------------------------
If Claude Code runs on that box, the scope wall MUST be there. An agent on a datacenter IP with no
`enforce_scope.py` is strictly worse than no remote agent at all. So the wall is not one item in the
manifest — it is the reason the manifest exists, and `verify` fails loudly if it is missing.

USAGE
    python3 sync_workspace.py plan          # what would go, with sizes. Changes nothing.
    python3 sync_workspace.py push          # copy the framework to the remote host
    python3 sync_workspace.py verify        # prove the wall is present AND fires over there
    python3 sync_workspace.py engagement <name>   # opt in to ONE engagement's data, deliberately
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUCKET = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))

REMOTE_ROOT = "~/bug-bounty-workspace"

# ── TIER 1: the framework. Everything here is config, code, or methodology. No target data. ──
FRAMEWORK = [
    "global/CLAUDE.md",
    "global/OPERATING-MODES.md",
    "global/skills",
    "global/execution",
    "global/profiles",
    "global/platform-profiles",
    "global/operator-identity.md",
    "global/GOTCHA-pgrep-matches-itself.md",
    "CLAUDE.md",
    "OPERATING-MODES.md",
    "README.md",
    "templates",
    "testing",
    ".claude/hooks",            # THE SCOPE WALL — the reason this tool exists
    ".claude/settings.json",
    ".claude/production_tools.json",
    ".claude/skills",
    ".claude/state",
]

# ── TIER 2: per-engagement BOUNDARIES. Kilobytes. These are what the wall reads. ──
#
# Deliberately NOT: findings/, evidence, NOTES.md, or any numbered phase folder. Those are the
# target-derived material §2F-NET is about.
BOUNDARY_FILES = [
    "scope.md",
    "approved_TTPs.yaml",
    "README.md",
    "_STATUS.md",
    "facts.json",
]
BOUNDARY_DIRS = [".scope_lock"]

# ── NEVER, under any option. Not a default — a refusal. ──
#
# `_ACCOUNTS` holds account identifiers, which are the operator's and not the box's.
#
# The per-engagement never-ship list is read from a PRIVATE file rather than written here, because
# this module lives in a PUBLIC repository and naming a private/NDA program in public source is
# itself the disclosure the list exists to prevent. (Caught on 2026-07-28 in exactly that state —
# an NDA program's name hardcoded into the rule forbidding its disclosure.)
#
# Format: one path fragment per line, `#` comments allowed. Absent file = nothing extra refused.
NEVER_LIST_FILE = os.path.join(os.path.dirname(os.path.dirname(HERE)), ".never-ship")


def _load_never():
    never = ["_ACCOUNTS"]
    try:
        with open(NEVER_LIST_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    never.append(line)
    except OSError:
        pass
    return never


NEVER = _load_never()

WALL = ".claude/hooks/enforce_scope.py"


def _executor():
    from execution import settings as S            # noqa: PLC0415
    e = getattr(S, "EXECUTORS", None)
    if isinstance(e, dict) and e:
        name = getattr(S, "ACTIVE_EXECUTOR", None) or next(iter(e))
        return e[name] if isinstance(e.get(name), dict) else {"name": name, **e[name]}
    return {"name": "linode-dallas", "host": getattr(S, "REMOTE_HOST", "69.164.199.154"),
            "user": getattr(S, "REMOTE_USER", "recon")}


def _ssh_base():
    from execution import ssh_mux                  # noqa: PLC0415
    e = _executor()
    return ["ssh"] + ssh_mux.base_opts() + ["%s@%s" % (e["user"], e["host"])], e


def _size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.0f%s" % (n, unit)
        n /= 1024.0
    return "%.1fTB" % n


def _is_never(relpath):
    return any(n in relpath for n in NEVER)


def collect():
    """Return (items, skipped). Each item is a bucket-relative path that will be shipped."""
    items, skipped = [], []

    for rel in FRAMEWORK:
        p = os.path.join(BUCKET, rel)
        if os.path.exists(p):
            items.append(rel)
        else:
            skipped.append("absent: " + rel)

    eng_root = os.path.join(BUCKET, "engagements")
    for dirpath, dirnames, _ in os.walk(eng_root):
        if ".scope_lock" not in dirnames and not os.path.exists(
                os.path.join(dirpath, "approved_TTPs.yaml")):
            continue
        rel_eng = os.path.relpath(dirpath, BUCKET)
        if _is_never(rel_eng):
            skipped.append("REFUSED (never list): " + rel_eng)
            dirnames[:] = []
            continue
        for f in BOUNDARY_FILES:
            if os.path.isfile(os.path.join(dirpath, f)):
                items.append(os.path.join(rel_eng, f))
        for d in BOUNDARY_DIRS:
            if os.path.isdir(os.path.join(dirpath, d)):
                items.append(os.path.join(rel_eng, d))

    return items, skipped


def cmd_plan():
    items, skipped = collect()
    total = 0
    print("\n  WOULD SHIP to %s:%s\n" % (_executor()["host"], REMOTE_ROOT))
    for rel in items:
        s = _size(os.path.join(BUCKET, rel))
        total += s
        print("    %-8s %s" % (_human(s), rel))
    print("\n    %-8s TOTAL (%d items)" % (_human(total), len(items)))

    print("\n  DELIBERATELY LEFT BEHIND (target-derived — see §2F-NET):")
    print("    every numbered phase folder, findings/, evidence, NOTES.md, _NEEDS-REVIEW/")
    bucket_total = _size(BUCKET)
    print("    bucket is %s; this ships %s of it (%.1f%%)"
          % (_human(bucket_total), _human(total), 100.0 * total / max(bucket_total, 1)))
    if skipped:
        print("\n  SKIPPED:")
        for s in skipped:
            print("    " + s)
    print("\n  Nothing was copied. Run `push` to do it.")
    return 0


def cmd_push():
    items, skipped = collect()
    for s in skipped:
        if s.startswith("REFUSED"):
            print("  " + s)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in items:
            tf.add(os.path.join(BUCKET, rel), arcname=rel,
                   filter=lambda ti: None if ("__pycache__" in ti.name
                                              or ti.name.endswith(".pyc")) else ti)
    payload = buf.getvalue()

    ssh, e = _ssh_base()
    remote = ("mkdir -p %s && tar xzf - -C %s && echo OK" % (REMOTE_ROOT, REMOTE_ROOT))
    p = subprocess.run(ssh + [remote], input=payload, capture_output=True, timeout=300)
    out = p.stdout.decode(errors="replace")
    if "OK" not in out:
        print("  PUSH FAILED: %s" % (p.stderr.decode(errors="replace")[:400]))
        return 1
    print("  pushed %s (%d items) to %s:%s" % (_human(len(payload)), len(items), e["host"], REMOTE_ROOT))
    return cmd_verify()


def cmd_verify():
    """Prove the wall is present AND that it actually refuses. Presence alone is not proof."""
    ssh, e = _ssh_base()
    print("\n  VERIFY on %s" % e["host"])

    p = subprocess.run(ssh + ["test -f %s/%s && echo PRESENT || echo MISSING" % (REMOTE_ROOT, WALL)],
                       capture_output=True, text=True, timeout=60)
    present = "PRESENT" in p.stdout
    print("    scope wall file        : %s" % ("present" if present else "*** MISSING ***"))
    if not present:
        print("\n    STOP. Claude Code on this box would run with NO scope wall.")
        return 1

    # The test that matters: does it DENY? A file that exists but never refuses is not a wall.
    probe = ('cd %s && echo \'{"tool_name":"Bash","tool_input":{"command":"curl -s https://example.com/"},'
             '"cwd":"%s"}\' | python3 %s' % (REMOTE_ROOT, REMOTE_ROOT, WALL))
    p = subprocess.run(ssh + [probe], capture_output=True, text=True, timeout=60)
    denied = '"deny"' in p.stdout
    print("    wall refuses a probe   : %s" % ("yes" if denied else "*** NO — it allowed it ***"))
    if not denied:
        print("      returned: %s" % (p.stdout.strip()[:180] or "(nothing)"))
        print("\n    A wall that does not refuse is not a wall. Do not run agents here yet.")
        return 1

    p = subprocess.run(ssh + ["ls %s/engagements/programs/*/*/*/.scope_lock/enforcement.json "
                              "2>/dev/null | wc -l" % REMOTE_ROOT],
                       capture_output=True, text=True, timeout=60)
    print("    scope locks present    : %s" % p.stdout.strip())

    p = subprocess.run(ssh + ["du -sh %s 2>/dev/null | cut -f1" % REMOTE_ROOT],
                       capture_output=True, text=True, timeout=60)
    print("    remote workspace size  : %s" % p.stdout.strip())
    print("\n    OK — a session there has context, boundaries, and a wall that fires.")
    return 0


def cmd_engagement(name):
    """Opt IN to one engagement's data. Deliberate, per-engagement, never a default."""
    rel = name if name.startswith("programs/") else "programs/" + name
    src = os.path.join(BUCKET, "engagements", rel)
    if not os.path.isdir(src):
        print("  no such engagement: %s" % rel)
        return 2
    if _is_never(rel):
        print("  REFUSED: %s is on the never-ship list (NDA / closed). This is not overridable "
              "here — if it genuinely must move, that is an operator decision made somewhere "
              "more visible than a sync flag." % rel)
        return 1

    print("  This ships %s of TARGET-DERIVED material for %s to a rented host."
          % (_human(_size(src)), rel))
    print("  §2F-NET says the executor is a transient workspace, not storage. Pull it, work it,")
    print("  push results home, then purge — do not leave it there.")
    try:
        if input("  Type the engagement name to confirm: ").strip() != os.path.basename(rel):
            print("  cancelled.")
            return 1
    except (EOFError, KeyboardInterrupt):
        print("\n  cancelled.")
        return 1

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tf.add(src, arcname=os.path.join("engagements", rel),
               filter=lambda ti: None if "__pycache__" in ti.name else ti)
    ssh, e = _ssh_base()
    p = subprocess.run(ssh + ["mkdir -p %s && tar xzf - -C %s && echo OK" % (REMOTE_ROOT, REMOTE_ROOT)],
                       input=buf.getvalue(), capture_output=True, timeout=600)
    ok = "OK" in p.stdout.decode(errors="replace")
    print("  %s" % ("shipped." if ok else "FAILED: " + p.stderr.decode(errors="replace")[:300]))
    return 0 if ok else 1


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "plan"
    if cmd == "plan":
        return cmd_plan()
    if cmd == "push":
        return cmd_push()
    if cmd == "verify":
        return cmd_verify()
    if cmd == "engagement" and len(argv) > 2:
        return cmd_engagement(argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
