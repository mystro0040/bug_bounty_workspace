#!/usr/bin/env python3
"""tree_manifest — prove a directory tree survived a round trip.

THE PROBLEM. Moving a tree through an archive, an object store, or a sync is lossy in ways that
are silent. Every one of these has actually happened here:

  * `s3cmd sync` SKIPS SYMLINKS. It prints a warning among thousands of lines and carries on. A
    Python venv is mostly symlinks, so the venv arrives structurally intact and non-functional.
  * Zip does not store empty directories reliably, and a tool that expects `output/` to exist
    fails on a directory nobody noticed was gone.
  * The executable bit is lost by several transports. The file is present, byte-identical, and
    will not run.
  * A file can be truncated or corrupted mid-transfer and still look plausible by size.

None of that is caught by comparing file COUNTS, which is the check people reach for.

THE APPROACH. Before sending, record what is there — path, size, sha256, the executable bit,
symlink targets, and empty directories — into one JSON file. That file is small, travels with the
tree, and after arrival `verify` compares reality against it and says exactly what is wrong.

A manifest rather than a second copy of the tree, deliberately: a copy doubles the disk, doubles
the file count if it lands anywhere the sync can see, and still needs something to diff it.

REPAIR. A symlink is just a target string, so `verify --repair-symlinks` can rebuild every symlink
the transport dropped without needing the bytes. That is the single most useful thing here: it
turns a broken venv back into a working one in under a second.

Standalone and dependency-free on purpose — no AI required, no imports beyond the standard
library, one file you can copy anywhere. Run it by hand, from a script, or from a Makefile.

USAGE
    tree_manifest.py record <dir> [-o manifest.json] [--exclude GLOB]... [--no-hash]
    tree_manifest.py verify <dir> [-m manifest.json] [--repair-symlinks] [--quiet] [--json]

EXIT CODES
    0  the tree matches (extra files alone do not fail — new work is normal)
    1  something is missing, changed, or structurally lost
    2  the manifest could not be read
"""
import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import platform
import sys

MANIFEST_NAME = ".tree-manifest.json"
FORMAT_VERSION = 1

# Never record the manifest itself: it is written after the walk, so its own hash could never match.
ALWAYS_EXCLUDE = [MANIFEST_NAME, "*/" + MANIFEST_NAME]


def _excluded(rel, patterns):
    """fnmatch against the relative path, matching s3cmd's --exclude semantics closely enough.

    A pattern is tried against the whole relative path AND against each path segment, because
    people write both `__pycache__/*` and `*.pyc` and expect both to work.
    """
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        if fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
        # `__pycache__/*` should also catch `a/b/__pycache__/c.pyc`
        if "/" in pat and fnmatch.fnmatch(rel, "*/" + pat):
            return True
    return False


def _sha256(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def walk_tree(root, excludes, want_hash=True, progress=False):
    """Return {relpath: entry}. Entry types: f=file, l=symlink, d=empty directory."""
    entries = {}
    root = os.path.abspath(root)
    count = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""

        # Prune excluded directories so we do not descend into them at all.
        keep = []
        for d in dirnames:
            rel = os.path.join(rel_dir, d) if rel_dir else d
            if _excluded(rel + "/", excludes) or _excluded(rel, excludes):
                continue
            keep.append(d)
        dirnames[:] = keep

        # An empty directory is real structure that most transports drop.
        if not dirnames and not filenames and rel_dir:
            entries[rel_dir] = {"t": "d"}

        for name in filenames:
            rel = os.path.join(rel_dir, name) if rel_dir else name
            if _excluded(rel, excludes):
                continue
            full = os.path.join(dirpath, name)

            if os.path.islink(full):
                # Record the target, not the resolved content. The target string is what the
                # transport threw away and it is all we need to rebuild it.
                try:
                    entries[rel] = {"t": "l", "target": os.readlink(full)}
                except OSError:
                    pass
                continue

            try:
                st = os.stat(full)
            except OSError:
                continue

            entry = {"t": "f", "s": st.st_size, "x": bool(st.st_mode & 0o111)}
            if want_hash:
                try:
                    entry["h"] = _sha256(full)
                except OSError:
                    entry["h"] = None
            entries[rel] = entry

            count += 1
            if progress and count % 2000 == 0:
                print(f"    ... {count} files", file=sys.stderr)

    # A symlink pointing at a directory is not walked into (followlinks=False), but os.walk lists
    # it under dirnames rather than filenames, so catch those separately.
    for dirpath, dirnames, _files in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if not os.path.islink(full):
                continue
            rel = os.path.join(rel_dir, d) if rel_dir else d
            if _excluded(rel, excludes):
                continue
            try:
                entries[rel] = {"t": "l", "target": os.readlink(full)}
            except OSError:
                pass

    return entries


def cmd_record(args):
    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        print(f"[!] not a directory: {root}", file=sys.stderr)
        return 2

    excludes = list(ALWAYS_EXCLUDE) + list(args.exclude or [])
    if args.exclude_from:
        with open(args.exclude_from) as fh:
            excludes += [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    print(f"[+] recording {root}")
    entries = walk_tree(root, excludes, want_hash=not args.no_hash, progress=True)

    files = sum(1 for e in entries.values() if e["t"] == "f")
    links = sum(1 for e in entries.values() if e["t"] == "l")
    empty = sum(1 for e in entries.values() if e["t"] == "d")

    manifest = {
        "format": FORMAT_VERSION,
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "machine": platform.node(),
        "root_name": os.path.basename(root),
        "hashed": not args.no_hash,
        "excludes": excludes,
        "counts": {"files": files, "symlinks": links, "empty_dirs": empty},
        "entries": entries,
    }

    out = args.output or os.path.join(root, MANIFEST_NAME)
    with open(out, "w") as fh:
        json.dump(manifest, fh, separators=(",", ":"), sort_keys=True)

    size_kb = os.path.getsize(out) / 1024.0
    print(f"[+] {files} files, {links} symlinks, {empty} empty dirs")
    print(f"[+] manifest: {out} ({size_kb:.0f} KB)")
    if not args.no_hash:
        print("[i] hashed — a verify will catch corruption, not just absence.")
    else:
        print("[!] --no-hash: a verify will catch MISSING files but NOT corrupted ones.")
    return 0


def cmd_verify(args):
    root = os.path.abspath(args.directory)
    path = args.manifest or os.path.join(root, MANIFEST_NAME)

    try:
        with open(path) as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[!] cannot read manifest {path}: {exc}", file=sys.stderr)
        print("[i] Record one BEFORE the transfer — there is nothing to compare against after.",
              file=sys.stderr)
        return 2

    recorded = manifest.get("entries", {})
    excludes = manifest.get("excludes", list(ALWAYS_EXCLUDE))
    hashed = manifest.get("hashed", True)

    print(f"[+] verifying {root}")
    print(f"[i] manifest from {manifest.get('machine','?')} at {manifest.get('created','?')}")
    actual = walk_tree(root, excludes, want_hash=hashed, progress=True)

    missing, changed, exec_lost, link_lost, emptydir_lost, extra = [], [], [], [], [], []

    for rel, want in recorded.items():
        have = actual.get(rel)

        if have is None:
            if want["t"] == "l":
                link_lost.append((rel, want.get("target", "?")))
            elif want["t"] == "d":
                emptydir_lost.append(rel)
            else:
                missing.append(rel)
            continue

        if want["t"] == "l":
            if have["t"] != "l":
                # Present but no longer a link — some transports materialise a copy instead.
                link_lost.append((rel, want.get("target", "?")))
            elif have.get("target") != want.get("target"):
                changed.append(f"{rel} (symlink target: {want.get('target')} -> {have.get('target')})")
            continue

        if want["t"] == "f":
            if have["t"] != "f":
                missing.append(rel)
                continue
            if hashed and want.get("h") and have.get("h") and want["h"] != have["h"]:
                changed.append(f"{rel} (content differs)")
            elif not hashed and want.get("s") != have.get("s"):
                changed.append(f"{rel} (size {want.get('s')} -> {have.get('s')})")
            if want.get("x") and not have.get("x"):
                exec_lost.append(rel)

    for rel in actual:
        if rel not in recorded:
            extra.append(rel)

    repaired = []
    if args.repair_symlinks and link_lost:
        for rel, target in link_lost:
            full = os.path.join(root, rel)
            try:
                if os.path.exists(full) or os.path.islink(full):
                    if os.path.islink(full):
                        os.unlink(full)
                    else:
                        continue  # a real file sits there; do not destroy it silently
                os.makedirs(os.path.dirname(full), exist_ok=True)
                os.symlink(target, full)
                repaired.append(rel)
            except OSError as exc:
                print(f"    [!] could not repair {rel}: {exc}")
        link_lost = [(r, t) for r, t in link_lost if r not in repaired]

    def report(title, items, limit=15, fmt=str):
        if not items:
            return
        print(f"\n  {title}: {len(items)}")
        for item in items[:limit]:
            print(f"    {fmt(item)}")
        if len(items) > limit:
            print(f"    ... and {len(items) - limit} more")

    print()
    report("MISSING (in manifest, absent here)", missing)
    report("CHANGED (content differs)", changed)
    report("SYMLINKS LOST", link_lost, fmt=lambda p: f"{p[0]} -> {p[1]}")
    report("EXECUTABLE BIT LOST", exec_lost)
    report("EMPTY DIRECTORIES LOST", emptydir_lost)
    if repaired:
        report("SYMLINKS REPAIRED", repaired)
    if not args.quiet:
        report("EXTRA (here, not in manifest — usually new work)", extra, limit=10)

    broken = len(missing) + len(changed) + len(link_lost) + len(exec_lost) + len(emptydir_lost)

    if args.json:
        print(json.dumps({
            "missing": missing, "changed": changed,
            "symlinks_lost": [list(x) for x in link_lost],
            "exec_lost": exec_lost, "empty_dirs_lost": emptydir_lost,
            "repaired": repaired, "extra_count": len(extra), "broken": broken,
        }, indent=1))

    print()
    if broken == 0:
        print(f"[PASS] tree intact — {len(recorded)} entries verified"
              + (f", {len(extra)} new" if extra else "") + ".")
        return 0

    print(f"[FAIL] {broken} problem(s). The tree did NOT survive intact.")
    if link_lost:
        print("[i] Symlinks are the usual casualty of an object-store sync.")
        print("    Re-run with --repair-symlinks to rebuild them from the manifest.")
    if missing or changed:
        print("[i] Missing or changed CONTENT cannot be repaired from a manifest — it only")
        print("    records what was there. Restore those from the source or an archive.")
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="Prove a directory tree survived a transfer.",
        epilog="Record before sending, verify after arrival.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rec = sub.add_parser("record", help="record what is in a tree, before sending it")
    rec.add_argument("directory")
    rec.add_argument("-o", "--output", help=f"manifest path (default: <dir>/{MANIFEST_NAME})")
    rec.add_argument("--exclude", action="append", help="glob to skip (repeatable)")
    rec.add_argument("--exclude-from", help="file of globs to skip, one per line")
    rec.add_argument("--no-hash", action="store_true",
                     help="skip hashing: much faster, catches absence but not corruption")
    rec.set_defaults(func=cmd_record)

    ver = sub.add_parser("verify", help="check a tree against its manifest, after arrival")
    ver.add_argument("directory")
    ver.add_argument("-m", "--manifest", help=f"manifest path (default: <dir>/{MANIFEST_NAME})")
    ver.add_argument("--repair-symlinks", action="store_true",
                     help="rebuild symlinks the transport dropped, from the recorded targets")
    ver.add_argument("--quiet", action="store_true", help="do not list extra files")
    ver.add_argument("--json", action="store_true", help="also emit a machine-readable summary")
    ver.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
