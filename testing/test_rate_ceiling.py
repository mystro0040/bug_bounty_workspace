#!/usr/bin/env python3
"""test_rate_ceiling.py — the program's rate limit is enforced BY THE WALL, not just the library.

WHY THIS EXISTS
  The ceiling lived only in scope_compiler._clamp_rates(), which rewrites rate flags in the
  compiled TTP command templates. Commands generated from approved_TTPs.yaml were clamped;
  anything typed by hand was not, because enforcement.json never carried the ceiling and the
  hook had nothing to compare against.

  Measured 2026-07-27 against a lock documenting 5 req/s:
      -rl 5  ALLOWED     -rl 50  ALLOWED     -rl 99  ALLOWED     -rl 150 denied
  Up to 20x the program's stated limit passed the wall, caught only by the hard DoS floor.

  A rate limit is a term of the engagement — the same tier as scope and "no tools from the home
  network". Always on, unless the operator explicitly says otherwise.

SELF-CONTAINED BY DESIGN
  This builds its own throwaway engagement in a temp dir. An earlier draft pointed at a real
  engagement and passed in the bucket while failing in the public repo, which ships no
  engagements. A test that only works in one checkout is a test that gets deleted.
"""
import json, os, shutil, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude", "hooks", "enforce_scope.py")
ENG = "programs/test/rate-ceiling-fixture"
CEILING = 5

_PASS = _FAIL = 0


def build_project(tmp, ceiling=CEILING, include_ceiling=True):
    """A minimal workspace the hook can read: shields up, one approved engagement."""
    os.makedirs(os.path.join(tmp, "global"), exist_ok=True)
    with open(os.path.join(tmp, "global", "CLAUDE.md"), "w", encoding="utf-8") as fh:
        fh.write("- **HARD_BOUNDARIES** (safety valve): `true`\n")
    lock_dir = os.path.join(tmp, "engagements", ENG, ".scope_lock")
    os.makedirs(lock_dir, exist_ok=True)
    enf = {
        "engagement": "rate-ceiling-fixture",
        "approved": True,
        "allowed_binaries": ["httpx", "dnsx", "nuclei", "naabu", "ffuf", "katana", "curl"],
        "always_allowed_extra": [],
        "denied_patterns": [],
        "assets": {"hosts": ["target.example"], "wildcards": [], "cidrs": [], "ips": [],
                   "endpoints": [], "out_of_scope": []},
    }
    if include_ceiling:
        enf["rate_ceiling"] = ceiling
    with open(os.path.join(lock_dir, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump(enf, fh, indent=2)
    return tmp


def decide(cmd, project):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project, AO_ENGAGEMENT=ENG)
    p = subprocess.run([sys.executable, HOOK], input=json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": project}),
        capture_output=True, text=True, env=env)
    try:
        out = json.loads(p.stdout or "{}")
    except ValueError:
        return "?", (p.stderr or "")[:120]
    hs = out.get("hookSpecificOutput") or {}
    return hs.get("permissionDecision", "?"), hs.get("permissionDecisionReason", "")


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (f"  -> {extra}" if (extra and not ok) else ""))


def main():
    tmp = tempfile.mkdtemp(prefix="rate-ceiling-")
    try:
        proj = build_project(tmp)
        print(f"[rate ceiling] wall enforces the engagement's stated limit ({CEILING} req/s)")

        # Every alias family. A tool's short and long forms are the SAME option, so checking one
        # spelling is how `-rate-limit 5 … -rl 20` once shipped with an effective rate of 20.
        over = [
            ("httpx -rl 50            (10x)", "httpx -u https://target.example -rl 50"),
            ("httpx -rate-limit 20     (4x)", "httpx -u https://target.example -rate-limit 20"),
            ("nuclei -rl 6      (just over)", "nuclei -u https://target.example -rl 6"),
            ("naabu -rate 99          (20x)", "naabu -host target.example -rate 99"),
            ("ffuf -rate 30            (6x)", "ffuf -u https://target.example/FUZZ -rate 30"),
            ("katana -rl 40            (8x)", "katana -u https://target.example -rl 40"),
            # A chain is checked WHOLE: a compliant first segment must not license the rest.
            ("chain: compliant && over     ",
             "httpx -u https://target.example -rl 5 && nuclei -u https://target.example -rl 80"),
        ]
        for name, cmd in over:
            d, why = decide(cmd, proj)
            chk(f"{name} denied", d == "deny" and "ceiling" in why, f"{d}: {why[:60]}")

        print("\n  -- negative controls: compliant commands MUST still run --")
        under = [
            ("httpx -rl 5   (exactly at the limit)", "httpx -u https://target.example -rl 5"),
            ("httpx -rl 1                   (under)", "httpx -u https://target.example -rl 1"),
            ("dnsx -rate-limit 5         (at limit)", "dnsx -rate-limit 5 -d target.example"),
            ("no rate flag present at all          ", "curl -sS https://target.example/"),
        ]
        for name, cmd in under:
            d, why = decide(cmd, proj)
            chk(f"{name} allowed", d == "allow", f"{d}: {why[:60]}")

        print("\n  -- a lock with NO ceiling must not silently allow anything --")
        tmp2 = tempfile.mkdtemp(prefix="rate-ceiling-none-")
        try:
            proj2 = build_project(tmp2, include_ceiling=False)
            d, _ = decide("httpx -u https://target.example -rl 900", proj2)
            # 900 is over the hard DoS floor, so it must still die even with no ceiling present.
            chk("no ceiling: the hard DoS floor still fires", d == "deny", d)
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)

        print(f"\n{_PASS}/{_PASS + _FAIL} passed")
        return 1 if _FAIL else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
