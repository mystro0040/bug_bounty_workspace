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
                    Also VERIFIES the tree against its manifest and rebuilds dropped symlinks.

Round-trip verification (also runs automatically as part of --zip and --restore):
  --manifest        record path/size/sha256/exec-bit/symlink-target/empty-dirs for the whole
                    bucket into _sync/tree-manifest.json. Run on the SENDING machine, before push.
  --verify          compare the tree against that manifest after a pull. Add --repair to rebuild
                    symlinks the transport dropped. Exit 1 if anything is missing or changed.

Why a manifest and not a file count: the sync is lossy in ways a count cannot see. s3cmd SKIPS
SYMLINKS (a venv arrives structurally present and non-functional), zip drops empty directories,
and several transports lose the executable bit. This bucket currently has 30 empty directories
that a count would never miss. The underlying tool is standalone with no dependencies, so it runs
by hand on any machine, with or without an agent — which matters because this routine propagates
to the manual workspaces where there is no agent at all.

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

    WHY IT IS NOT A CONSTANT. It was one — a hardcoded absolute path to the bug-bounty bucket, with
    nothing parsing `--bucket` at all. Two live consequences, both from the same line:

      1. A copy of this script in another bucket still staged and DELETED inside the bug-bounty
         bucket, which the operator was not looking at.
      2. The test suite passes `--bucket <tempdir>` and states in its own docstring that "nothing
         here touches a real bucket". The flag was ignored, so every run of the suite operated on
         the REAL bucket: it silently rewrote the real tree-manifest.json, and `--zip --yes` would
         have zipped and removed real directories the moment one matched. It had simply never
         matched yet, which is luck rather than safety.

    Both were properties asserted in prose that no code implemented. Resolution happens at import,
    before any other module-level path is derived from it, so there is no window in which half the
    constants point at one tree and half at another.

    The pentest workspace's copy already worked this way; this brings the two back into step.
    """
    chosen = None
    for i, a in enumerate(argv):
        if a == "--bucket" and i + 1 < len(argv):
            chosen = argv[i + 1]
            break
        if a.startswith("--bucket="):
            chosen = a.split("=", 1)[1]
            break
    if chosen is None:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    resolved = os.path.abspath(os.path.expanduser(chosen))
    # This tool removes directories, so being handed a wrong or empty path is the expensive
    # mistake. "Has a _sync/ directory" is the cheapest available sanity check — a real bucket
    # always does, because that is where this script lives.
    if not os.path.isdir(resolved):
        sys.exit(f"[!] --bucket {resolved} is not a directory. Refusing.")
    if not os.path.isdir(os.path.join(resolved, "_sync")):
        sys.exit(f"[!] --bucket {resolved} has no _sync/ directory, so it does not look like a "
                 "bucket.\n    Refusing rather than staging or deleting inside an unknown tree.")
    return resolved


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


# --------------------------------------------------------------------------------------------
# Round-trip verification.
#
# The zip step above proves each ARCHIVE is intact. It says nothing about whether the rest of the
# bucket survived the sync — and the sync is the lossy part. s3cmd silently skips symlinks, empty
# directories do not survive a zip, and the executable bit is dropped by several transports. A
# file COUNT, which is what everyone reaches for, sees none of that.
#
# So: record a manifest before pushing, verify against it after pulling. tree_manifest is a
# standalone general-purpose tool with no dependencies — it can be run by hand on any machine,
# with or without an agent driving it. That matters because this same routine propagates to the
# manual workspaces, where there is no agent at all.

MANIFEST_TOOL_CANDIDATES = [
    os.path.expanduser("~/Workspace/Production_Ready/private/General_Development/"
                       "general_utils/tree_manifest/tree_manifest.py"),
    os.path.join(BUCKET, "global", "toolchain", "tree_manifest.py"),
]

TREE_MANIFEST = os.path.join(SYNC_DIR, "tree-manifest.json")

# Must mirror the sync's own exclusions. Recording a file the sync then refuses to carry would
# make every verify report it as MISSING — the fastest way to teach someone to ignore a checker.
MANIFEST_EXCLUDES = [
    "__pycache__/*", "*.pyc", "*.pyo", "*.pyd",
    ".pytest_cache/*", ".mypy_cache/*", ".ruff_cache/*",
    "*.egg-info/*", ".DS_Store", "Thumbs.db", "*.swp", "*.swo", "*~",
    "*/sandbox/*/venv/*", "*/sandbox/*/.venv/*", "*/node_modules/*",
    # Any venv anywhere — must stay in step with SYNC_EXCLUDES in s3_utils.py, or the manifest
    # records files the sync refuses to carry and every verify reports them MISSING.
    # NOTE the trailing `*` on the directory name, for the same reason it is there in
    # SYNC_EXCLUDES: `*/venv/*` matches a directory called exactly `venv`, and the venv that
    # prompted the fix was named `venv-sftp`. `venv*` covers venv, venv-sftp, venv3, .venv.
    "*/venv*/*", "venv*/*", "*/.venv*/*", ".venv*/*",
    "*/site-packages/*", "*/__pypackages__/*",
    "*/pyvenv.cfg", "pyvenv.cfg",
    ".git/*",
    # The manifest is written after the walk, so it can never be in its own record. Left in, it
    # shows up as a spurious "1 new" on every single verify — small, permanent, and exactly the
    # kind of constant noise that trains someone to stop reading the output.
    "_sync/tree-manifest.json",
]


# The comment above says these two lists "must stay in step". That sentence had been sitting there
# for a day when a forced pull reverted this file to an older copy and put them out of step — and
# nothing noticed, because nothing was checking. A rule with no code behind it is the failure mode
# this workspace keeps paying for, so here is the code.
#
# It reads s3_utils.py rather than importing it, for two reasons that are both about this file
# working ALONE: importing would drag in sync_guard and sync_digest, and on a machine that has the
# bucket but not the general_utils repo there is nothing to import at all. A missing s3_utils is
# not an error here — it means "cannot check from this machine", which is said out loud rather
# than reported as agreement.

SYNC_SOURCE_CANDIDATES = [
    os.path.expanduser("~/Workspace/Production_Ready/private/General_Development/"
                       "general_utils/vault-sync-manager/s3_utils.py"),
]


def _sync_excludes_from_source():
    """SYNC_EXCLUDES as s3_utils.py actually defines it, or None if it cannot be read here."""
    import ast

    for path in SYNC_SOURCE_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except (OSError, SyntaxError):
            return None
        found = []
        for node in ast.walk(tree):
            # Covers both `SYNC_EXCLUDES = [...]` and the later `SYNC_EXCLUDES += [...]`.
            target = None
            value = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AugAssign):
                target, value = node.target, node.value
            if not isinstance(target, ast.Name) or target.id != "SYNC_EXCLUDES":
                continue
            if not isinstance(value, ast.List):
                return None
            for element in value.elts:
                if isinstance(element, ast.Constant) and isinstance(element.value, str):
                    found.append(element.value)
        return found or None
    return None


def check_excludes_in_step(quiet=False):
    """Warn when the manifest would record files the sync refuses to carry.

    Returns True when in step or unable to check, False on real drift. The asymmetry is
    deliberate: MANIFEST_EXCLUDES is allowed EXTRAS (.git, the manifest itself), because skipping
    something the sync does carry only makes the verify less thorough. The direction that breaks
    is the other one — a pattern the sync excludes but the manifest records, which makes every
    single verify report MISSING files that were never going to be there, and that is exactly how
    someone learns to ignore a checker.
    """
    sync_patterns = _sync_excludes_from_source()
    if sync_patterns is None:
        if not quiet:
            print("[i] Could not read SYNC_EXCLUDES from s3_utils.py on this machine — "
                  "exclude drift not checked.")
        return True

    missing = [p for p in sync_patterns if p not in MANIFEST_EXCLUDES]
    if not missing:
        return True

    print("\n[!] EXCLUDE DRIFT — the sync skips patterns this manifest still records:")
    for pattern in missing:
        print(f"      {pattern}")
    print("    Every --verify will report those as MISSING even though nothing is wrong.")
    print("    Fix: add them to MANIFEST_EXCLUDES in this file.\n")
    return False


def _manifest_tool():
    for path in MANIFEST_TOOL_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _run_manifest(mode, extra=()):
    tool = _manifest_tool()
    if not tool:
        print("[!] tree_manifest.py not found on this machine. Looked in:")
        for path in MANIFEST_TOOL_CANDIDATES:
            print(f"      {path}")
        print("[i] Skipping round-trip verification — the zips are still verified.")
        return False

    import subprocess
    sys.stdout.flush()      # the child writes straight to fd 1; unflushed headers land after it
    cmd = [sys.executable, tool, mode, BUCKET, ("-o" if mode == "record" else "-m"), TREE_MANIFEST]
    for pat in MANIFEST_EXCLUDES:
        if mode == "record":
            cmd += ["--exclude", pat]
    cmd += list(extra)
    return subprocess.run(cmd).returncode == 0


def do_manifest():
    print("\n=== recording the tree manifest (run this BEFORE pushing) ===")
    check_excludes_in_step()
    return _run_manifest("record")


def do_verify(repair=True):
    print("\n=== verifying the tree against its manifest (run this AFTER pulling) ===")
    if not os.path.exists(TREE_MANIFEST):
        print(f"[!] no manifest at {TREE_MANIFEST}")
        print("[i] Nothing to verify against. The manifest has to be recorded on the SENDING")
        print("    machine, before the push. Run --manifest there, then push.")
        return False
    # Checked here as well as on record, because a verify is where the drift becomes VISIBLE — as
    # a list of MISSING files that are not actually missing. Saying why, at the moment the
    # confusing output appears, is worth more than saying it earlier on the other machine.
    check_excludes_in_step()
    extra = ["--quiet"] + (["--repair-symlinks"] if repair else [])
    return _run_manifest("verify", extra)


def main():
    # --bucket was already consumed at import time by _resolve_bucket, which had to happen before
    # any module-level path derived from it. Drop it and its value here so neither is mistaken for
    # a mode flag.
    argv, skip = [], False
    for a in sys.argv[1:]:
        if skip:
            skip = False
            continue
        if a == "--bucket":
            skip = True
            continue
        if a.startswith("--bucket="):
            continue
        argv.append(a)

    args = set(argv)
    if "--restore" in args:
        do_restore()
        # Restore is the receiving side, which is exactly when a loss shows up. Verify without
        # being asked: an integrity check nobody remembers to run protects nothing.
        do_verify(repair=True)
    elif "--zip" in args:
        do_zip("--yes" in args)
        # Record AFTER zipping, so the manifest describes the tree that will actually be pushed.
        do_manifest()
    elif "--manifest" in args:
        do_manifest()
    elif "--verify" in args:
        sys.exit(0 if do_verify(repair="--repair" in args) else 1)
    else:
        do_scan()
        print("\n(--scan only. Use --zip to stage, --restore to unzip.)")
        print("Round-trip check: --manifest before a push, --verify after a pull.")


if __name__ == "__main__":
    main()
