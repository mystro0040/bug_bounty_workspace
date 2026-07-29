#!/usr/bin/env python3
"""The opsec check must be able to FAIL. That is the whole test.

A pre-flight check that always comes back clean is worse than no check, because it converts "we
never looked" into "we looked and it was fine". So almost every case here BREAKS something and
asserts the specific check catches it — and the last group asserts the three design rules hold:
UNKNOWN is not a pass, a crashing check is not a pass, and a not-clean run exits non-zero.

Isolated: builds a fake bucket + fake HOME in a temp dir and runs the real script inside it.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "QUICK-ACCESS", "opsec_check.py")

DENY_HOOK = '''import json, sys
sys.stdin.read()
print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny",
                                         "permissionDecisionReason": "out of scope"}}))
'''
ALLOW_HOOK = "import sys\nsys.stdin.read()\n"          # prints nothing = allowed

P = F = 0


def check(label, cond, detail=""):
    global P, F
    if cond:
        P += 1
        print("  ok   %s" % label)
    else:
        F += 1
        print("  FAIL %s" % label + ("\n         %s" % detail if detail else ""))


def build(tmp, *, register_wall=True, hook=DENY_HOOK, settings_valid=True,
          engagement="programs/test/eng", lock=True, assets=("a.test",), approved=True):
    """A minimal bucket + HOME the script can run against."""
    home = os.path.join(tmp, "home")
    bucket = os.path.join(home, "Workspace", "buckets", "b")
    os.makedirs(os.path.join(bucket, "QUICK-ACCESS"))
    os.makedirs(os.path.join(bucket, ".claude", "hooks"))
    os.makedirs(os.path.join(bucket, ".claude", "state"))
    os.makedirs(os.path.join(bucket, "global"))
    shutil.copy(REAL, os.path.join(bucket, "QUICK-ACCESS", "opsec_check.py"))

    if hook is not None:
        with open(os.path.join(bucket, ".claude", "hooks", "enforce_scope.py"), "w") as fh:
            fh.write(hook)

    os.makedirs(os.path.join(home, ".claude"))
    settings = os.path.join(home, ".claude", "settings.json")
    if settings_valid:
        body = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "python3 %s" %
             ("/x/enforce_scope.py" if register_wall else "/x/other.py")}]}]}}
        with open(settings, "w") as fh:
            json.dump(body, fh)
    else:
        with open(settings, "w") as fh:
            fh.write("{not json")

    with open(os.path.join(bucket, ".claude", "state", "active_engagement"), "w") as fh:
        fh.write(engagement)

    if lock:
        d = os.path.join(bucket, "engagements", engagement, ".scope_lock")
        os.makedirs(d)
        with open(os.path.join(d, "enforcement.json"), "w") as fh:
            json.dump({"engagement": "eng", "approved": str(approved),
                       "allowed_binaries": ["curl"], "rate_ceiling": "5",
                       "assets": {"hosts": list(assets), "wildcards": [], "cidrs": [],
                                  "ips": [], "endpoints": [], "out_of_scope": []}}, fh)

    with open(os.path.join(bucket, "global", "operator-identity.md"), "w") as fh:
        fh.write("| Platform | Handle | Header |\n|---|---|---|\n| HackerOne | `h` | `X-B: h` |\n")
    return home, bucket


def run(bucket, home, *args, env_extra=None):
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("AO_ENGAGEMENT", None)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, os.path.join(bucket, "QUICK-ACCESS", "opsec_check.py"),
                        "--json"], capture_output=True, text=True, env=env, timeout=180)
    try:
        return json.loads(p.stdout), p.returncode
    except Exception:
        return {"parse_error": p.stdout + p.stderr, "results": []}, p.returncode


def state_of(report, name):
    for r in report.get("results", []):
        if r["check"] == name:
            return r["state"]
    return None


def main():
    print("opsec check — can it fail?\n")

    print("the wall")
    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, register_wall=False)
        rep, _ = run(bucket, home)
        check("unregistered hook -> FAIL", state_of(rep, "wall registered") == "FAIL",
              str(rep)[:200])

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, settings_valid=False)
        rep, _ = run(bucket, home)
        check("corrupt settings.json -> FAIL", state_of(rep, "wall registered") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, hook=ALLOW_HOOK)
        rep, _ = run(bucket, home)
        check("hook that ALLOWS out-of-scope -> FAIL", state_of(rep, "wall fires") == "FAIL",
              "registration passes but enforcement does not — the six-day bug")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, hook=None)
        rep, _ = run(bucket, home)
        check("missing hook file -> FAIL", state_of(rep, "wall fires") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        rep, _ = run(bucket, home)
        check("working hook -> OK", state_of(rep, "wall fires") == "OK")

    print("\nengagement posture")
    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, lock=False)
        rep, _ = run(bucket, home)
        check("engagement with no scope lock -> FAIL", state_of(rep, "engagement loaded") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, assets=())
        rep, _ = run(bucket, home)
        check("scope lock with zero assets -> FAIL", state_of(rep, "engagement loaded") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, approved=False)
        rep, _ = run(bucket, home)
        check("unapproved scope lock -> WARN", state_of(rep, "engagement loaded") == "WARN")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, engagement="")
        rep, _ = run(bucket, home)
        check("no engagement selected -> WARN, not FAIL",
              state_of(rep, "engagement loaded") == "WARN")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp, assets=("a.test", "b.test", "c.test"))
        rep, _ = run(bucket, home)
        detail = [r["detail"] for r in rep["results"] if r["check"] == "engagement loaded"][0]
        # the dict has 6 category keys; counting the dict would say "6 assets" for 3 assets
        check("asset count counts ASSETS, not category keys", "3 in-scope assets" in detail, detail)
        check("rate ceiling is surfaced", "rate ceiling 5" in detail, detail)

    print("\ncredential separation")
    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        rep, _ = run(bucket, home, env_extra={"ANTHROPIC_API_KEY": "sk-ant-test"})
        check("API key in the environment -> FAIL",
              state_of(rep, "no API key on this machine") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        os.makedirs(os.path.join(home, "ai-orchestrator", "orchestrator", "api_runtime"))
        rep, _ = run(bucket, home)
        check("cloud-only api_runtime present here -> FAIL",
              state_of(rep, "no API key on this machine") == "FAIL")

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        rep, _ = run(bucket, home)
        check("clean machine -> OK", state_of(rep, "no API key on this machine") == "OK")

    print("\nthe three design rules")
    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        rep, rc = run(bucket, home)
        # the fake bucket has no global/execution, so those checks cannot determine an answer
        unknowns = [r["check"] for r in rep["results"] if r["state"] == "UNKNOWN"]
        check("undeterminable checks report UNKNOWN", bool(unknowns), str(rep)[:200])
        check("UNKNOWN alone makes the run NOT clean", rep["clean"] is False,
              "unknowns=%s" % unknowns)
        check("not clean -> exit code 1", rc == 1)

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        # make one check raise, by making its target unreadable in a way it does not guard
        path = os.path.join(bucket, "QUICK-ACCESS", "opsec_check.py")
        src = open(path).read().replace(
            "def check_ram():", "def check_ram():\n    raise RuntimeError('boom')")
        open(path, "w").write(src)
        rep, rc = run(bucket, home)
        check("a crashing check reports FAIL, not silence",
              state_of(rep, "check_ram") == "FAIL", str(rep)[:200])
        check("a crashing check makes the run not clean", rep["clean"] is False)

    with tempfile.TemporaryDirectory() as tmp:
        home, bucket = build(tmp)
        rep, _ = run(bucket, home)
        missing = [r["check"] for r in rep["results"]
                   if r["state"] in ("OK", "FAIL") and not r["examined"]]
        check("every OK/FAIL says what it examined", not missing, "no evidence: %s" % missing)

    print("\n%d passed, %d failed" % (P, F))
    return 1 if F else 0


if __name__ == "__main__":
    raise SystemExit(main())
