#!/usr/bin/env python3
"""test_learning_loop.py — the ladder holds in both directions.

The operator's two stated worries, pinned as tests:

  1. "I wouldn't want to leave a comment or two and then, based on those one or two comments,
     change how it acts permanently."  ->  one occurrence must NOT promote, and staging a
     single-occurrence lesson must be refused.

  2. "we could be locked into a particular scope ... so we can transfer from one to the other
     just in case we get into this learning loop that's not ideal"  ->  scope must move in BOTH
     directions, and retiring must keep the reason rather than deleting the record.

Plus the one that protects the operator's authority: staging must never APPLY anything.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(HERE)
TOOL = os.path.join(WORKSPACE, "global", "learning", "lessons.py")

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def run(store, *args):
    """Run the tool against a throwaway store by pointing it at a copied tree."""
    env = dict(os.environ)
    proc = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True,
                          text=True, env=env, cwd=store, timeout=30)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    # The tool resolves its store relative to its own file, so run against a full copy of the
    # global/learning tree in a temp dir. That keeps the real lessons untouched.
    tmp = tempfile.mkdtemp(prefix="lessons-")
    try:
        learn = os.path.join(tmp, "global", "learning")
        os.makedirs(learn)
        shutil.copy(TOOL, os.path.join(learn, "lessons.py"))
        tool = os.path.join(learn, "lessons.py")

        def call(*args):
            proc = subprocess.run([sys.executable, tool] + list(args),
                                  capture_output=True, text=True, timeout=30)
            return proc.returncode, proc.stdout + proc.stderr

        print("[loop] one occurrence changes nothing — the operator's explicit worry")
        rc, out = call("add", "a thing I noticed once", "--name", "once",
                       "--evidence", "it happened")
        chk("adding succeeds", rc == 0, out)
        chk("status is 'observed', not a rule", "observed" in out, out)
        chk("and it says so plainly", "changes nothing" in out.lower() or "Recorded only" in out, out)

        rc, out = call("stage", "once")
        chk("staging a single-occurrence lesson is REFUSED", rc == 1, out)
        chk("and explains the threshold", "more than once" in out, out)

        print("\n[loop] a second occurrence is what promotes it")
        rc, out = call("evidence", "once", "it happened again, differently")
        chk("evidence is recorded", rc == 0 and "2 occurrence" in out, out)
        chk("and it announces the promotion", "PROMOTED" in out, out)

        rc, out = call("stage", "once")
        chk("now staging succeeds", rc == 0, out)
        chk("staging says it did NOT apply anything", "NOT applied" in out, out)

        print("\n[loop] staging writes a proposal and changes nothing else")
        nr = os.path.join(tmp, "_NEEDS-REVIEW")
        staged = os.listdir(nr) if os.path.isdir(nr) else []
        chk("a _NEEDS-REVIEW file was written", len(staged) == 1, staged)
        if staged:
            text = open(os.path.join(nr, staged[0])).read()
            chk("the proposal carries the EVIDENCE, not just the claim",
                "it happened again" in text, text[:200])
            chk("it states what a yes changes", "What a yes changes" in text)
            chk("and what a no changes", "What a no changes" in text)

        print("\n[loop] scope moves BOTH ways — the lock-in worry")
        rc, out = call("rescope", "once", "--to", "platform", "--because", "did not generalise")
        chk("a lesson can be NARROWED", rc == 0 and "general -> platform" in out, out)
        chk("narrowing is framed as the loop working, not a failure",
            "working" in out.lower(), out)
        rc, out = call("rescope", "once", "--to", "general", "--because", "it does generalise")
        chk("and widened again", rc == 0 and "platform -> general" in out, out)

        print("\n[loop] retiring keeps the record")
        rc, out = call("retire", "once", "--because", "turned out to be wrong")
        chk("retire succeeds", rc == 0, out)
        body = open(os.path.join(learn, "lessons", "once.md")).read()
        chk("the file still exists", os.path.exists(os.path.join(learn, "lessons", "once.md")))
        chk("the reason is recorded in it", "turned out to be wrong" in body, body[:200])
        chk("the original claim is still readable", "a thing I noticed once" in body, body[:200])

        rc, out = call("list")
        chk("a retired lesson is hidden from the default list", "once" not in out, out)
        rc, out = call("list", "--all")
        chk("but --all still shows it", "once" in out, out)

        print("\n[loop] an operator-stated rule skips the anecdote stage")
        rc, out = call("add", "the operator said do this", "--name", "stated", "--rule")
        chk("--rule starts as a candidate", "candidate" in out, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
