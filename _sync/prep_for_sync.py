#!/usr/bin/env python3
"""
prep_for_sync.py — stage heavy bucket directories into VERIFIED zips before a sync, so the
sync carries a few archives instead of tens of thousands of small files (file *count*, not
size, is what makes a bucket sync slow).

Part of the work-machine -> home sync workflow. CONFIRM-FIRST by design:
  --scan            list heavy dirs + sizes/counts, change NOTHING   (safe, read-only)
  --zip [--yes]     for each: zip AS-IS (local test edits preserved) -> VERIFY -> remove the
                    raw dir -> record in _sync/SYNC-MANIFEST.md. Without --yes it prompts.
  --restore         unzip every archive in _sync/archives/ back to its original location
                    (receiving/home side, or to resume local testing on the work machine).

A heavy dir = one named 'repos'/'node_modules' (re-derivable clones/deps). The zip preserves
the working tree exactly, including any modifications made for testing — that is why we zip
rather than exclude-and-re-clone (re-cloning would discard local edits).

The raw dir is removed ONLY after the zip verifies (testzip + entry count). The zip is the
preserved copy; `--restore` puts it back byte-for-byte.
"""
import os, sys, zipfile, hashlib, shutil, datetime


def _resolve_bucket(argv):
    """The bucket root this run operates on.

    Derived from THIS FILE's location (the parent of the `_sync/` directory holding it), so the
    same script works in any bucket instead of only the one it was written in. `--bucket PATH`
    overrides, which is what the tests use.

    Deriving rather than hardcoding matters for a tool that DELETES directories: a stale hardcoded
    path would make a copy running in bucket B quietly stage and remove things in bucket A.
    """
    for i, a in enumerate(argv):
        if a == "--bucket" and i + 1 < len(argv):
            return os.path.abspath(os.path.expanduser(argv[i + 1]))
        if a.startswith("--bucket="):
            return os.path.abspath(os.path.expanduser(a.split("=", 1)[1]))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BUCKET = _resolve_bucket(sys.argv[1:])
SYNC_DIR = os.path.join(BUCKET, "_sync")
ARCHIVE_DIR = os.path.join(SYNC_DIR, "archives")
MANIFEST = os.path.join(SYNC_DIR, "SYNC-MANIFEST.md")
HEAVY_NAMES = {"repos", "node_modules"}
SKIP = {"_sync", ".git"}


def dir_stats(path):
    n = size = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                size += os.path.getsize(os.path.join(root, f)); n += 1
            except OSError:
                pass
    return n, size


def human(size):
    s = float(size)
    for u in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.1f}{u}"
        s /= 1024
    return f"{s:.1f}TB"


def find_candidates():
    cands, start = [], os.path.join(BUCKET, "engagements")
    for root, dirs, _files in os.walk(start):
        base = os.path.basename(root)
        if base in SKIP:
            dirs[:] = []
            continue
        if base in HEAVY_NAMES:
            n, size = dir_stats(root)
            cands.append((root, n, size))
            dirs[:] = []          # do not recurse into a captured candidate
    return sorted(cands, key=lambda c: -c[2])


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def zip_dir(path):
    parent = os.path.dirname(path)
    arcname = os.path.relpath(path, BUCKET).replace(os.sep, "__") + ".zip"
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    zpath = os.path.join(ARCHIVE_DIR, arcname)
    count = 0
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for root, _dirs, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    z.write(fp, os.path.relpath(fp, parent))   # top entry = <dirname>/...
                    count += 1
                except OSError:
                    pass
    return zpath, count, parent


def verify_zip(zpath, expected):
    with zipfile.ZipFile(zpath) as z:
        if z.testzip() is not None:
            return False, "corrupt entry"
        got = sum(1 for n in z.namelist() if not n.endswith("/"))
    return (got >= expected), f"{got} entries (expected >= {expected})"


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def append_manifest(entry):
    header = ("# SYNC-MANIFEST — archives staged by prep_for_sync.py\n\n"
              "> The receiving/home agent restores with `python3 _sync/prep_for_sync.py --restore`\n"
              "> (or unzips each archive to the `unzip-to` path below). Each archive preserves the\n"
              "> tree AS-IS, including any local test modifications. Versions/tags for cloned repos\n"
              "> are recorded in that engagement's `02_Reconnaissance/00-REPO-INVENTORY.md`.\n\n")
    if not os.path.exists(MANIFEST):
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            fh.write(header)
    with open(MANIFEST, "a", encoding="utf-8") as fh:
        fh.write(entry)


def do_scan():
    cands = find_candidates()
    if not cands:
        print("no heavy dirs found — nothing to stage.")
        return cands
    print("Heavy dirs (candidates to zip before sync):")
    for path, n, size in cands:
        print(f"  {os.path.relpath(path, BUCKET):60s} {n:>7d} files  {human(size):>9s}")
    return cands


def do_zip(auto_yes):
    cands = do_scan()
    if not cands:
        return
    if not auto_yes:
        ans = input("\nZip + verify + remove these raw dirs? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted — nothing changed.")
            return
    for path, n, _size in cands:
        rel = os.path.relpath(path, BUCKET)
        print(f"\nzipping {rel} ({n} files) ...")
        zpath, count, parent = zip_dir(path)
        ok, msg = verify_zip(zpath, n)
        if not ok:
            print(f"  !! VERIFY FAILED ({msg}) — raw dir KEPT, zip left for inspection: {zpath}")
            continue
        digest = sha256(zpath)
        zsize = os.path.getsize(zpath)
        shutil.rmtree(path)
        print(f"  verified {msg}; sha256 {digest[:16]}…; {human(zsize)}; raw dir removed.")
        append_manifest(
            f"## {os.path.basename(zpath)}\n"
            f"- staged: {now()}\n"
            f"- archive: `_sync/archives/{os.path.basename(zpath)}`  ({human(zsize)}, {count} files)\n"
            f"- unzip-to: `{os.path.relpath(parent, BUCKET)}/`  (restores `{os.path.basename(path)}/`)\n"
            f"- sha256: `{digest}`\n"
            f"- notes: re-derivable clone/deps; local test edits preserved. For a JS repo, build with "
            f"`npm install --ignore-scripts` at the pinned tag (see the engagement's REPO-INVENTORY).\n\n")
    print(f"\ndone. Manifest: {MANIFEST}")
    print("The bucket now carries the zip(s) instead of the raw tree — sync will be fast.")


def do_restore():
    if not os.path.isdir(ARCHIVE_DIR):
        print("no _sync/archives/ — nothing to restore.")
        return
    for name in sorted(os.listdir(ARCHIVE_DIR)):
        if not name.endswith(".zip"):
            continue
        zpath = os.path.join(ARCHIVE_DIR, name)
        parent_rel = name[:-4].replace("__", os.sep)
        parent = os.path.join(BUCKET, os.path.dirname(parent_rel))
        os.makedirs(parent, exist_ok=True)
        print(f"restoring {name} -> {os.path.relpath(parent, BUCKET)}/ ...")
        with zipfile.ZipFile(zpath) as z:
            if z.testzip() is not None:
                print("  !! corrupt archive — skipped."); continue
            z.extractall(parent)
        print("  done.")
    print("restore complete. (Archives left in _sync/archives/; delete when you no longer need them.)")


def main():
    args = set(sys.argv[1:])
    if "--restore" in args:
        do_restore()
    elif "--zip" in args:
        do_zip("--yes" in args)
    else:
        do_scan()
        print("\n(--scan only. Use --zip to stage, --restore to unzip.)")


if __name__ == "__main__":
    main()
