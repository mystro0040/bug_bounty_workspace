#!/usr/bin/env python3
"""Tests for _sync/prep_for_sync.py — the "get it ready for syncing" routine.

Why this suite exists: the tool DELETES directories. It zips a heavy re-derivable tree, verifies
the archive, and only then removes the original. Every check below is aimed at that ordering, at
the one directory name that must never be touched, and at the root-resolution change that lets the
same script run in more than one bucket.

Runs the real script as a subprocess against a synthetic bucket in a temp dir. Nothing here touches
a real bucket.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = os.path.join(REPO, "_sync", "prep_for_sync.py")

failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"  [ok]   {label}")
    else:
        print(f"  [FAIL] {label}   {detail}")
        failures.append(label)


def run(bucket, *args):
    proc = subprocess.run([sys.executable, TOOL, *args, "--bucket", bucket],
                          capture_output=True, text=True, timeout=180)
    return proc.returncode, proc.stdout + proc.stderr


def make_bucket(tmp, with_temp_dir=False, heavy_files=12):
    """A bucket-shaped tree: engagements/<eng>/02_Reconnaissance/repos/ with real content."""
    bucket = os.path.join(tmp, "synthetic-bucket")
    repos = os.path.join(bucket, "engagements", "programs", "synthetic",
                         "02_Reconnaissance", "repos")
    os.makedirs(os.path.join(repos, "proj", "src"), exist_ok=True)
    os.makedirs(os.path.join(bucket, "_sync"), exist_ok=True)
    for i in range(heavy_files):
        with open(os.path.join(repos, "proj", "src", f"f{i}.txt"), "w") as fh:
            fh.write(f"content number {i}\n" * 4)
    # a local test edit — the whole reason the tool zips rather than re-clones
    with open(os.path.join(repos, "proj", "LOCAL-EDIT.txt"), "w") as fh:
        fh.write("modified locally, must survive the round trip\n")
    # a normal engagement file that must NOT be staged
    with open(os.path.join(bucket, "engagements", "programs", "synthetic", "NOTES.md"), "w") as fh:
        fh.write("notes\n")
    if with_temp_dir:
        t = os.path.join(bucket, "engagements", "programs", "synthetic", "temp")
        os.makedirs(t, exist_ok=True)
        for i in range(heavy_files):
            with open(os.path.join(t, f"safety-copy-{i}.md"), "w") as fh:
                fh.write("operator safety copy — must never be staged or deleted\n")
    return bucket, repos


def tree_snapshot(path):
    out = {}
    for root, _dirs, files in os.walk(path):
        for f in files:
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, path)] = fh.read()
    return out


# ---------------------------------------------------------------- 1. scan is read-only
def test_scan_finds_heavy_and_changes_nothing():
    print("[prep] --scan lists the heavy dir and changes nothing")
    with tempfile.TemporaryDirectory() as tmp:
        bucket, repos = make_bucket(tmp)
        before = tree_snapshot(bucket)
        rc, out = run(bucket, "--scan")
        check("exits 0", rc == 0, out[:200])
        check("names the heavy 'repos' dir", "repos" in out, out[:200])
        check("does not name the engagement's NOTES.md", "NOTES.md" not in out)
        check("changed nothing on disk", tree_snapshot(bucket) == before)


# ---------------------------------------------------------------- 2. the temp rule
def test_temp_dir_is_never_a_candidate():
    print("[prep] a 'temp' directory is never staged, however heavy")
    with tempfile.TemporaryDirectory() as tmp:
        bucket, _ = make_bucket(tmp, with_temp_dir=True)
        temp_dir = os.path.join(bucket, "engagements", "programs", "synthetic", "temp")
        rc, out = run(bucket, "--scan")
        check("scan does not offer 'temp'", "/temp" not in out and "temp " not in out, out[:200])
        rc, out = run(bucket, "--zip", "--yes")
        check("zip exits 0", rc == 0, out[:200])
        check("temp/ still exists after a zip run", os.path.isdir(temp_dir))
        check("temp/ contents intact", len(os.listdir(temp_dir)) == 12)
        archives = os.listdir(os.path.join(bucket, "_sync", "archives"))
        check("no archive was made from temp", not any("temp" in a for a in archives),
              str(archives))


# ---------------------------------------------------------------- 3. verify BEFORE delete
def test_zip_verifies_then_removes_and_records():
    print("[prep] --zip verifies the archive, then removes the raw dir, then records it")
    with tempfile.TemporaryDirectory() as tmp:
        bucket, repos = make_bucket(tmp)
        original = tree_snapshot(repos)
        rc, out = run(bucket, "--zip", "--yes")
        check("exits 0", rc == 0, out[:300])
        check("raw dir removed after verification", not os.path.exists(repos))

        adir = os.path.join(bucket, "_sync", "archives")
        archives = [a for a in os.listdir(adir) if a.endswith(".zip")]
        check("exactly one archive produced", len(archives) == 1, str(archives))
        if archives:
            with zipfile.ZipFile(os.path.join(adir, archives[0])) as z:
                check("archive passes testzip", z.testzip() is None)
                check("archive holds every original file",
                      len(z.namelist()) == len(original),
                      f"{len(z.namelist())} vs {len(original)}")

        manifest = os.path.join(bucket, "_sync", "SYNC-MANIFEST.md")
        check("manifest written", os.path.isfile(manifest))
        if os.path.isfile(manifest):
            text = open(manifest).read()
            check("manifest records a sha256", "sha256" in text and len(text) > 100)
            check("manifest records where it unzips to", "unzip-to" in text)


# ---------------------------------------------------------------- 4. round trip
def test_restore_round_trips_byte_for_byte():
    print("[prep] --restore puts the tree back byte-for-byte, local edits included")
    with tempfile.TemporaryDirectory() as tmp:
        bucket, repos = make_bucket(tmp)
        original = tree_snapshot(repos)
        run(bucket, "--zip", "--yes")
        rc, out = run(bucket, "--restore")
        check("restore exits 0", rc == 0, out[:200])
        check("raw dir is back", os.path.isdir(repos))
        if os.path.isdir(repos):
            restored = tree_snapshot(repos)
            check("every file identical after round trip", restored == original,
                  f"{len(restored)} files vs {len(original)}")
            edit = os.path.join(repos, "proj", "LOCAL-EDIT.txt")
            check("the local test edit survived", os.path.isfile(edit))


# ---------------------------------------------------------------- 5. corrupt archive
def test_corrupt_archive_is_refused_not_half_extracted():
    print("[prep] a corrupt archive is refused rather than half-restored")
    with tempfile.TemporaryDirectory() as tmp:
        bucket, repos = make_bucket(tmp)
        run(bucket, "--zip", "--yes")
        adir = os.path.join(bucket, "_sync", "archives")
        archive = os.path.join(adir, [a for a in os.listdir(adir) if a.endswith(".zip")][0])
        with open(archive, "r+b") as fh:      # corrupt the middle, keep the central directory
            fh.seek(64)
            fh.write(b"\x00" * 64)
        rc, out = run(bucket, "--restore")
        check("run does not crash", rc == 0, out[:200])
        check("reports the archive as corrupt, or extracts nothing",
              "corrupt" in out.lower() or not os.path.exists(repos), out[:200])


# ---------------------------------------------------------------- 6. root resolution
def test_bucket_root_is_derived_not_hardcoded():
    print("[prep] the bucket root is derived from the script's location, not hardcoded")
    src = open(TOOL).read()
    check("no hardcoded absolute bucket path",
          "/home/primaryu/Workspace/buckets/" not in src,
          "a hardcoded path would make a copy in bucket B operate on bucket A")
    check("root is derived from __file__", "__file__" in src)
    with tempfile.TemporaryDirectory() as tmp:
        bucket, _ = make_bucket(tmp)
        # a second bucket the run must NOT touch
        other, other_repos = make_bucket(os.path.join(tmp, "second"))
        os.makedirs(os.path.join(tmp, "second"), exist_ok=True)
        before = tree_snapshot(other)
        run(bucket, "--zip", "--yes")
        check("the other bucket was untouched", tree_snapshot(other) == before)


def main():
    print(f"prep_for_sync suite — {TOOL}")
    if not os.path.isfile(TOOL):
        print(f"  [FAIL] tool not found at {TOOL}")
        return 1
    for fn in (test_scan_finds_heavy_and_changes_nothing,
               test_temp_dir_is_never_a_candidate,
               test_zip_verifies_then_removes_and_records,
               test_restore_round_trips_byte_for_byte,
               test_corrupt_archive_is_refused_not_half_extracted,
               test_bucket_root_is_derived_not_hardcoded):
        fn()
    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
