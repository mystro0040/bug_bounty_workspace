#!/usr/bin/env python3
"""
test_scope_wall.py — the PreToolUse hook is driven, not read.

Every check here runs the real `.claude/hooks/enforce_scope.py` as a subprocess against a
synthetic engagement, exactly as Claude Code would. That matters: the defect this file was
written for was invisible to inspection but obvious the moment the hook was executed.

  On 2026-07-26 the word "approved" appeared eleven times in enforce_scope.py — every one a
  comment or a deny-string, never a lookup. `/generate-scope` writes `approved: false`, and the
  skill documented the consequence: "The hook refuses everything against an unapproved profile,
  so generating one changes nothing about what may run. That is why generation is safe for an
  agent to perform on request." Driving the hook with a synthetic `approved: false` profile
  allowed `nuclei` against an in-scope host. An agent running /generate-scope was arming the
  scope it had just written for itself.

The negative controls are not decoration. A wall that refuses everything passes every
"was it blocked?" test and is useless, so each lockdown check is paired with a proof that the
same command runs once the profile is approved.

Pure stdlib, no network, temp dirs only. Run:  python3 testing/test_scope_wall.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(HERE)
HOOK = os.path.join(WORKSPACE, ".claude", "hooks", "enforce_scope.py")

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def sandbox(approved, allowed=("curl", "httpx", "nuclei"), hosts=("acme.example",)):
    """A throwaway project dir with one compiled engagement."""
    root = tempfile.mkdtemp(prefix="scopewall-")
    eng = os.path.join(root, "engagements", "programs", "synthetic", ".scope_lock")
    os.makedirs(eng)
    os.makedirs(os.path.join(root, ".claude", "state"))
    with open(os.path.join(eng, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "engagement": "synthetic",
            "approved": approved,
            "source_scope_sha256": "0" * 64,
            "allowed_binaries": list(allowed),
            "always_allowed_extra": [],
            "denied_patterns": [r"\bhydra\b"],
            "assets": {"hosts": list(hosts), "wildcards": [], "cidrs": [], "ips": [],
                       "endpoints": [], "out_of_scope": []},
        }, fh)
    with open(os.path.join(root, ".claude", "state", "active_engagement"), "w") as fh:
        fh.write("programs/synthetic")
    return root


def decide(root, command):
    """Run the hook the way the harness does. Returns (decision, reason)."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root})
    env = dict(os.environ, AO_ENGAGEMENT="programs/synthetic", CLAUDE_PROJECT_DIR=root)
    proc = subprocess.run([sys.executable, HOOK], input=payload, env=env,
                          capture_output=True, text=True, timeout=30)
    try:
        out = json.loads(proc.stdout)["hookSpecificOutput"]
    except (ValueError, KeyError):
        return "MALFORMED", (proc.stdout or proc.stderr)[:300]
    return out["permissionDecision"], out.get("permissionDecisionReason", "")


# =============================================================================
def test_unapproved_profile_grants_nothing():
    print("[wall] a compiled-but-unapproved profile arms nothing")
    root = sandbox(approved=False)
    try:
        d, why = decide(root, "nuclei -u https://acme.example")
        chk("offensive tooling on an in-scope host is DENIED", d == "deny", (d, why[:120]))
        chk("the refusal says the scope is unapproved, not out-of-scope",
            "NOT APPROVED" in why, why[:160])
        chk("the refusal names the command that approves it",
            "approve" in why, why[:160])

        # Phase-1 lockdown, not a blanket refusal — an engagement still has to be preparable.
        d, _ = decide(root, "ls engagements/")
        chk("local setup work is still permitted", d == "allow", d)

        # The deny-list can only ever subtract, so it applies before approval too.
        d, why = decide(root, "hydra -l a -P b acme.example")
        chk("the hard-coded floor still fires while unapproved", d == "deny", (d, why[:80]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_approval_actually_opens_the_gate():
    """The other half. Without this, 'deny everything' would score full marks above."""
    print("[wall] approval opens the gate — and only as far as the profile says")
    root = sandbox(approved=True)
    try:
        d, why = decide(root, "nuclei -u https://acme.example")
        chk("the SAME command now runs once approved", d == "allow", (d, why[:120]))

        d, why = decide(root, "nuclei -u https://evil.invalid")
        chk("the asset boundary still holds", d == "deny", (d, why[:80]))
        chk("and says so for the right reason", "OUTSIDE" in why, why[:120])

        d, why = decide(root, "sqlmap -u https://acme.example")
        chk("a binary outside the allow-list is still denied", d == "deny", (d, why[:80]))
        chk("and says so for the right reason", "allow-list" in why, why[:120])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_approved_key_is_treated_as_unapproved():
    """Fail-closed on an older lock that predates the field.

    A lock written before the approval gate existed has no `approved` key at all. Absent must
    mean unapproved — the alternative is that every stale lock on disk silently counts as
    approved, which is the same hole in a different shape.
    """
    print("[wall] a lock with no approved key is unapproved, not approved-by-default")
    root = sandbox(approved=True)
    try:
        lock = os.path.join(root, "engagements", "programs", "synthetic",
                            ".scope_lock", "enforcement.json")
        data = json.load(open(lock))
        del data["approved"]
        json.dump(data, open(lock, "w"))

        d, why = decide(root, "nuclei -u https://acme.example")
        chk("absent approved key denies", d == "deny", (d, why[:120]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_non_boolean_approved_does_not_slip_through():
    """Only a real JSON `true` counts.

    `"approved": "false"` is a non-empty string and therefore truthy under bool() — a lock
    hand-edited to be OFF would have silently armed the wall. `1` is rejected for the same
    reason: the field records a decision, not a flag, and near-misses should fail closed.
    """
    print("[wall] approval is a boolean, and truthy junk does not count")
    for value, should_allow in (("false", False), ("true", False), ("", False),
                                (0, False), (1, False), (True, True)):
        root = sandbox(approved=True)
        try:
            lock = os.path.join(root, "engagements", "programs", "synthetic",
                                ".scope_lock", "enforcement.json")
            data = json.load(open(lock))
            data["approved"] = value
            json.dump(data, open(lock, "w"))
            d, _ = decide(root, "nuclei -u https://acme.example")
            label = f"approved={value!r} -> {'allow' if should_allow else 'deny'}"
            chk(label, (d == "allow") == should_allow, d)
        finally:
            shutil.rmtree(root, ignore_errors=True)


def main():
    if not os.path.isfile(HOOK):
        print(f"hook not found at {HOOK}")
        return 2
    for t in (test_unapproved_profile_grants_nothing,
              test_approval_actually_opens_the_gate,
              test_missing_approved_key_is_treated_as_unapproved,
              test_non_boolean_approved_does_not_slip_through):
        t()
    print(f"\n{_PASS}/{_PASS + _FAIL} passed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
