#!/usr/bin/env python3
"""test_wildcard_apex.py — `*.example.com` covers SUBDOMAINS, not the bare apex.

WHY THIS EXISTS
  dest_allowed() matched wildcards with:

      base = w[2:] if w.startswith("*.") else w
      if d == base or d.endswith("." + base):      # <-- `d == base` admitted the APEX

  so every wildcard silently authorised its own apex. That is more permissive than three separate
  things that all say otherwise:

    * CLAUDE.md §1B  — "A wildcard (*.example.com) -> SUBDOMAINS are in scope"
    * Hard rule #1   — "When in doubt, it is out of scope"
    * the scope files themselves — programs list bare hosts ALONGSIDE wildcards. Epic's scope has
      13 explicit hosts next to 30 wildcards. Two notations are used because they mean two
      different things; treating them as one discards the program's own wording.

  Measured 2026-07-28: 44 apexes across 5 live engagements were reachable ONLY through this
  behaviour — targets no program had listed. None had been contacted, so the exposure was
  prospective, and no compiled TTP template depended on it.

  This is the third prose-vs-code split found in two days, after the rate ceiling and the execution
  location. It is the one that leaned toward MORE access rather than less.

WHAT MUST NOT REGRESS
  An apex the program DOES list stays in scope — it appears in assets["hosts"] and is matched by the
  exact-host loop. The fix removes an inferred grant, never a stated one. Half these checks exist to
  hold that line.

SELF-CONTAINED: builds a throwaway workspace in a temp dir. No engagement, no executor, no packets.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude", "hooks", "enforce_scope.py")
ENG = "programs/test/wildcard-apex-fixture"

if not os.path.isfile(HOOK):
    print(f"SKIP: no enforcement hook at {HOOK} — this suite belongs in a workspace checkout.")
    sys.exit(0)

_PASS = _FAIL = 0


def check(label, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {label}")
    else:
        _FAIL += 1
        print(f"  FAIL {label}" + (f"\n         {detail}" if detail else ""))


def build(tmp, hosts, wildcards):
    os.makedirs(os.path.join(tmp, "global"), exist_ok=True)
    with open(os.path.join(tmp, "global", "CLAUDE.md"), "w", encoding="utf-8") as fh:
        fh.write("- **HARD_BOUNDARIES** (safety valve): `true`\n")
    lock = os.path.join(tmp, "engagements", ENG, ".scope_lock")
    os.makedirs(lock, exist_ok=True)
    with open(os.path.join(lock, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump({"engagement": "wildcard-apex-fixture", "approved": True,
                   "allowed_binaries": ["httpx", "curl", "nuclei", "dnsx"],
                   "always_allowed_extra": [], "denied_patterns": [], "rate_ceiling": 5,
                   "assets": {"hosts": hosts, "wildcards": wildcards, "cidrs": [], "ips": [],
                              "endpoints": [], "out_of_scope": []}}, fh)
    return tmp


def ask(tmp, command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": tmp})
    env = dict(os.environ, CLAUDE_PROJECT_DIR=tmp, AO_ENGAGEMENT=ENG,
               AO_REMOTE_DISPATCH="1")            # bypass the LOCATION check; not what we test here
    r = subprocess.run([sys.executable, HOOK], input=payload, capture_output=True,
                       text=True, env=env, timeout=60)
    try:
        d = json.loads(r.stdout)["hookSpecificOutput"]
        return d.get("permissionDecision", "?"), d.get("permissionDecisionReason", "")
    except (ValueError, KeyError):
        return "PARSE-ERROR", (r.stdout or r.stderr)[:200]


def main():
    print("=" * 78)
    print("test_wildcard_apex — a wildcard covers subdomains, not the apex")
    print("=" * 78)
    tmp = tempfile.mkdtemp(prefix="apextest-")
    try:
        # wildcard only; the apex is deliberately NOT in hosts
        build(tmp, hosts=["listed.example.org"], wildcards=["*.example.com"])

        print("\n[1] the bare apex is DENIED when only the wildcard covers it")
        for cmd in ("httpx -u https://example.com -rl 5",
                    "curl -sSI https://example.com/",
                    "nuclei -u http://example.com -rl 5"):
            d, why = ask(tmp, cmd)
            check(f"denied: {cmd[:38]}", d == "deny" and "OUTSIDE the approved asset scope" in why,
                  f"{d}: {why[:120]}")

        print("\n[2] the denial EXPLAINS the apex-vs-wildcard distinction")
        _, why = ask(tmp, "httpx -u https://example.com -rl 5")
        check("says a wildcard covers subdomains only", "SUBDOMAINS" in why, why[:160])
        check("tells the operator how to add it properly", "generate-scope" in why, why[:160])
        check("says not to infer it", "do not infer" in why.lower(), why[:200])

        print("\n[3] SUBDOMAINS of that wildcard are still allowed — the grant is intact")
        for host in ("www.example.com", "api.example.com", "a.b.deep.example.com"):
            d, why = ask(tmp, f"httpx -u https://{host} -rl 5")
            check(f"allowed: {host}", d == "allow", f"{d}: {why[:110]}")

        print("\n[4] an apex the program DOES list stays in scope")
        t2 = build(tempfile.mkdtemp(prefix="apextest-listed-"),
                   hosts=["example.com", "listed.example.org"], wildcards=["*.example.com"])
        d, why = ask(t2, "httpx -u https://example.com -rl 5")
        check("explicitly-listed apex allowed", d == "allow", f"{d}: {why[:120]}")
        d, _ = ask(t2, "httpx -u https://www.example.com -rl 5")
        check("its subdomains still allowed too", d == "allow")
        shutil.rmtree(t2, ignore_errors=True)

        print("\n[5] near-miss names must NOT be admitted by suffix confusion")
        # notexample.com ends with "example.com" as a STRING but is a different domain.
        for host in ("notexample.com", "evil-example.com", "example.com.attacker.net"):
            d, why = ask(tmp, f"httpx -u https://{host} -rl 5")
            check(f"denied: {host}", d == "deny", f"{d}: {why[:110]}")

        print("\n[6] an unrelated host is still denied (sanity)")
        d, _ = ask(tmp, "httpx -u https://elsewhere.test -rl 5")
        check("denied: elsewhere.test", d == "deny")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 78)
    print(f"{_PASS} passed, {_FAIL} failed")
    print("=" * 78)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
