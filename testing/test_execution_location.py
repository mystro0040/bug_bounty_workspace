#!/usr/bin/env python3
"""test_execution_location.py — network tools run ON THE EXECUTOR, enforced by the wall.

WHY THIS EXISTS
  The operator's standing rule is "no tools running on my home network", stated as being the same
  tier as scope itself. It was documented in CLAUDE.md §2F-NET and in remote_exec.py — in both
  places as a rule the AGENT FOLLOWS:

      "Nothing routes automatically. A tool you invoke through Bash runs HERE, on the home IP,
       no matter what the mode says."

  Nothing enforced it. Measured 2026-07-27 with execution resolving to remote, a hand-typed
  `httpx -u https://<in-scope-host> -rl 5` was ALLOWED — in-scope host, compliant rate — and would
  have put scanner traffic on the operator's residential line. The wall checked WHAT and HOW FAST.
  It never checked WHERE FROM.

  Third occurrence of one pattern: prose describing a protection no code implemented. Scope had a
  wall, rate got one on 2026-07-27, location gets one here.

THE HALF THAT MATTERS AS MUCH
  run_remote() validates the BARE tool command against this hook before wrapping it in SSH — so the
  asset wall can read the real targets instead of an opaque ssh string. That pre-flight is
  indistinguishable from an agent typing the command locally. Break that and remote execution stops
  working entirely, which would be far worse than the gap being closed. So this suite asserts the
  denial AND the dispatcher path, and a live end-to-end dispatch was run separately.

SELF-CONTAINED BY DESIGN
  Builds a throwaway workspace in a temp dir, including a stub execution/settings.py. No engagement,
  no executor, no packets. Runs identically in every checkout.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude", "hooks", "enforce_scope.py")
ENG = "programs/test/location-fixture"

# This suite tests the PreToolUse hook, which only the workspace repos ship — the framework repo
# is the read-only TTP library and has no hook. Without this guard, dropping the file in the wrong
# checkout produces 23 identical failures that look like a broken wall rather than a misplaced
# test. A test that cannot run should say so in one line, not fail loudly and ambiguously.
if not os.path.isfile(HOOK):
    print(f"SKIP: no enforcement hook at {HOOK}.\n"
          f"      This suite belongs in a workspace checkout (which ships .claude/hooks/), "
          f"not in the framework repo.")
    sys.exit(0)

_PASS = _FAIL = 0

SETTINGS_STUB = '''"""Stub settings for the location-wall fixture."""
def resolve_mode():
    return {mode!r}
'''


def check(label, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {label}")
    else:
        _FAIL += 1
        print(f"  FAIL {label}" + (f"\n         {detail}" if detail else ""))


def build(tmp, mode="remote", shields=True, with_settings=True, no_provisioning=False):
    """A minimal workspace the hook can read."""
    g = os.path.join(tmp, "global")
    os.makedirs(g, exist_ok=True)
    with open(os.path.join(g, "CLAUDE.md"), "w", encoding="utf-8") as fh:
        fh.write(f"- **HARD_BOUNDARIES** (safety valve): `{'true' if shields else 'false'}`\n")
    if with_settings:
        e = os.path.join(g, "execution")
        os.makedirs(e, exist_ok=True)
        open(os.path.join(e, "__init__.py"), "w").close()
        with open(os.path.join(e, "settings.py"), "w", encoding="utf-8") as fh:
            fh.write(SETTINGS_STUB.format(mode=mode))
    lock = os.path.join(tmp, "engagements", ENG, ".scope_lock")
    os.makedirs(lock, exist_ok=True)
    with open(os.path.join(lock, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "engagement": "location-fixture", "approved": True,
            "allowed_binaries": ["httpx", "dnsx", "nuclei", "curl", "wget", "grep", "python3",
                                 "subfinder", "gau", "ssh", "rsync", "cat", "sort", "katana"],
            "always_allowed_extra": [], "denied_patterns": [], "rate_ceiling": 5,
            # nodejs.org / registry.npmjs.org / pypi.org / deb.debian.org are here because the
            # provisioning exemption is about WHERE a fetch may run, not WHETHER the host is in
            # scope - the asset boundary still has to grant it, exactly as the operator granted
            # these on the real engagement. `assets_no_provisioning` below builds the same fixture
            # without them, to prove scope still governs.
            "assets": {"hosts": ["target.example"] + ([] if no_provisioning else [
                           "nodejs.org", "registry.npmjs.org", "pypi.org", "deb.debian.org"]),
                       "wildcards": [], "cidrs": [], "ips": [],
                       "endpoints": [], "out_of_scope": []},
        }, fh)
    return tmp


def ask(tmp, command, dispatch=False):
    """Run the hook, return (decision, reason)."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": tmp})
    env = dict(os.environ, CLAUDE_PROJECT_DIR=tmp, AO_ENGAGEMENT=ENG)
    env.pop("AO_REMOTE_DISPATCH", None)
    if dispatch:
        env["AO_REMOTE_DISPATCH"] = "1"
    r = subprocess.run([sys.executable, HOOK], input=payload, capture_output=True,
                       text=True, env=env, timeout=60)
    try:
        d = json.loads(r.stdout)["hookSpecificOutput"]
        return d.get("permissionDecision", "?"), d.get("permissionDecisionReason", "")
    except (ValueError, KeyError):
        return "PARSE-ERROR", (r.stdout or r.stderr)[:200]


def main():
    print("=" * 78)
    print("test_execution_location — network tools must run on the executor")
    print("=" * 78)
    tmp = tempfile.mkdtemp(prefix="loctest-")
    try:
        # ---------------------------------------------------------------- the wall itself
        print("\n[1] execution=remote: a bare network tool is DENIED")
        build(tmp, mode="remote")
        for cmd in ("httpx -u https://target.example -rl 5",
                    "dnsx -d target.example -rl 5",
                    "nuclei -u https://target.example -rl 5",
                    "katana -u https://target.example -rl 5",
                    "curl -sSI https://target.example"):
            d, why = ask(tmp, cmd)
            check(f"{cmd.split()[0]:9s} denied", d == "deny" and "network-facing" in why,
                  f"{d}: {why[:110]}")

        print("\n[2] the message says WHAT TO DO, not just no")
        _, why = ask(tmp, "httpx -u https://target.example -rl 5")
        check("names run_remote as the fix", "run_remote" in why, why[:140])
        check("names the deliberate override", "EXECUTE_MODE" in why, why[:140])

        print("\n[3] prefixes and chaining do not sneak past it")
        for cmd in ("FOO=1 httpx -u https://target.example -rl 5",
                    "nohup httpx -u https://target.example -rl 5",
                    "setsid httpx -u https://target.example -rl 5",
                    "cat hosts.txt && httpx -u https://target.example -rl 5",
                    "sort x.txt ; nuclei -u https://target.example -rl 5"):
            d, _ = ask(tmp, cmd)
            check(f"denied: {cmd[:46]}", d == "deny")

        print("\n[4] passive/aggregator tools are covered too (a deliberate call, see the hook)")
        for cmd in ("subfinder -d target.example", "gau target.example"):
            d, _ = ask(tmp, cmd)
            check(f"denied: {cmd.split()[0]}", d == "deny")

        # ------------------------------------------------- what must NOT have been broken
        print("\n[5] THE DISPATCHER STILL WORKS — break this and remote execution dies")
        d, why = ask(tmp, "httpx -u https://target.example -rl 5", dispatch=True)
        check("AO_REMOTE_DISPATCH=1 -> allowed", d == "allow", f"{d}: {why[:140]}")

        print("\n[6] ordinary local work is untouched")
        for cmd in ("grep -c target hosts.txt",
                    "python3 -c \"print(1)\"",
                    "cat results.json",
                    "curl -sS http://127.0.0.1:8000/",
                    "curl -sS http://localhost:9000/health"):
            d, why = ask(tmp, cmd)
            check(f"allowed: {cmd[:44]}", d == "allow", f"{d}: {why[:110]}")

        print("\n[6B] TOOLCHAIN PROVISIONING is not testing traffic (added 2026-07-29)")
        # A curl at a package/toolchain host reveals "this machine installs Node", never which
        # target it is interested in - so sending it to the executor is pointless and blocking it
        # made the agent conclude it was offline and stop. Scope is untouched: the host still has
        # to be in the engagement's assets to be reachable at all.
        for cmd in ("curl -fsSL https://nodejs.org/dist/v24.18.1/SHASUMS256.txt -o s.txt",
                    "curl -fSLO https://nodejs.org/dist/v24.18.1/node-v24.18.1-linux-x64.tar.xz",
                    "curl -sS https://registry.npmjs.org/next",
                    "curl -sS https://pypi.org/simple/requests/",
                    "wget https://deb.debian.org/debian/dists/stable/Release"):
            d, why = ask(tmp, cmd)
            check(f"provisioning allowed: {cmd.split()[1][:34]}", d == "allow", f"{d}: {why[:110]}")

        print("\n[6C] ...and the exemption is NARROW - these must all still be DENIED")
        # Exact authority match only. A lookalike host, a target host, and a mixed command that
        # smuggles a second destination alongside a provisioning one all have to fail.
        for label, cmd in (
            ("lookalike host", "curl -sS https://nodejs.org.evil.com/x"),
            ("subdomain of a provisioning host",
             "curl -sS https://evil.nodejs.org/x"),
            ("the engagement's own target", "curl -sSI https://target.example/"),
            ("mixed: provisioning + another host",
             "curl -sS https://nodejs.org/dist/index.json https://target.example/"),
            ("provisioning host but a SCANNER, not curl",
             "httpx -u https://nodejs.org -rl 5"),
            ("chained after a provisioning fetch",
             "curl -sS https://pypi.org/simple/ && httpx -u https://target.example -rl 5"),
        ):
            d, why = ask(tmp, cmd)
            check(f"denied: {label}", d == "deny", f"{d}: {why[:110]}")

        print("\n[6C-2] the exemption does NOT widen scope - an unapproved provisioning host still denies")
        # This is the property that keeps the exemption honest. On an engagement where the operator
        # has not approved nodejs.org, the asset boundary refuses it and the refusal names SCOPE,
        # not execution location. Approving it stays a deliberate, auditable operator decision.
        t_noprov = build(tempfile.mkdtemp(prefix="loctest-noprov-"), mode="remote",
                         no_provisioning=True)
        d, why = ask(t_noprov, "curl -fsSL https://nodejs.org/dist/index.json -o i.json")
        check("unapproved provisioning host is denied", d == "deny", f"{d}: {why[:110]}")
        check("denied by the ASSET boundary, not the location guard",
              "asset scope" in why and "network-facing" not in why, why[:140])
        shutil.rmtree(t_noprov, ignore_errors=True)

        print("\n[6D] VERIFICATION binaries are always allowed, without being in any scope-lock")
        # The allow-list is compiled from approved TTPs, and "scan the file I just downloaded" is
        # not a TTP - so without this, the scanner could never run on any engagement. Note the
        # fixture's allowed_binaries does NOT contain any of these.
        for cmd in ("clamscan /tmp/node-v24.18.1-linux-x64.tar.xz",
                    "sha512sum /tmp/artifact.bin",
                    "cksum /tmp/artifact.bin",
                    "gpgv /tmp/release.sig /tmp/release"):
            d, why = ask(tmp, cmd)
            check(f"allowed: {cmd.split()[0]}", d == "allow", f"{d}: {why[:110]}")
        for cmd in ("freshclam", "gpg --recv-keys ABCD1234"):
            d, _ = ask(tmp, cmd)
            check(f"still denied (can reach the network): {cmd.split()[0]}", d == "deny")

        print("\n[7] transport is not a local scan")
        d, why = ask(tmp, "rsync -az -e ssh out.txt recon@203.0.113.10:/home/recon/run/")
        check("rsync is not a location violation",
              "network-facing" not in why, why[:110])

        # -------------------------------------------------------------- mode sensitivity
        print("\n[8] execution=local: the check does not fire (tools are SUPPOSED to run here)")
        t2 = build(tempfile.mkdtemp(prefix="loctest-local-"), mode="local")
        d, why = ask(t2, "httpx -u https://target.example -rl 5")
        check("bare httpx allowed under local mode", d == "allow", f"{d}: {why[:110]}")
        shutil.rmtree(t2, ignore_errors=True)

        print("\n[9] no execution config at all -> cannot determine -> does NOT fire")
        # Asserted so this is a recorded DECISION rather than an accident. A checkout with no
        # execution package has no executor configured, so local is the correct behaviour there.
        # The dangerous case — settings present but unimportable — also breaks run_remote, so it
        # surfaces immediately rather than silently.
        t3 = build(tempfile.mkdtemp(prefix="loctest-none-"), with_settings=False)
        d, _ = ask(t3, "httpx -u https://target.example -rl 5")
        check("allowed when the mode is unknowable (documented, not accidental)", d == "allow")
        shutil.rmtree(t3, ignore_errors=True)

        print("\n[10] SHIELDS DOWN does not lift it")
        # Same reasoning as the rate ceiling: soft-boundary relaxes constraints we chose for
        # ourselves. Where the operator's traffic originates is not one of those.
        t4 = build(tempfile.mkdtemp(prefix="loctest-soft-"), mode="remote", shields=False)
        d, why = ask(t4, "httpx -u https://target.example -rl 5")
        check("still denied with HARD_BOUNDARIES=false", d == "deny", f"{d}: {why[:110]}")
        shutil.rmtree(t4, ignore_errors=True)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 78)
    print(f"{_PASS} passed, {_FAIL} failed")
    print("=" * 78)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
