#!/usr/bin/env python3
"""test_ssh_mux.py — SSH connection reuse is real, and it did not cost us anything else.

WHY THIS EXISTS
  One run_remote() call opened THIRTEEN SSH connections: 3 to push the input, 1 to run the
  command, 3 to encrypt, 4 to pull and verify, 2 to purge. ControlMaster collapses those into
  one authenticated session carrying thirteen channels.

  The risk in a change like this is not that it fails loudly. It is that it succeeds while
  quietly dropping something else on the way past — BatchMode, host-key checking, or the
  single-definition property that keeps three callers from drifting apart. So this suite
  asserts the optimisation AND the things it must not have touched.

WHAT THIS SUITE CANNOT PROVE
  That a real connection is genuinely reused, that a real remote exit code survives a
  multiplexed channel, and that a real stale socket recovers. Those need a live executor, and
  they were exercised against one — see testing/EXPECTATIONS.md and the smoke-test record in
  NOTES.md. Everything here runs offline and touches no network.

SELF-CONTAINED BY DESIGN
  No engagement, no executor, no packets. Runs identically in the bucket and in the public
  checkout.
"""
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The same modules live at `global/execution/` in the two workspace repos, and at
# `utilities/execution/` in the framework repo — where this file sits in `utilities/testing/`,
# so its sibling is the package root. Resolve rather than assume: a suite that only runs in one
# checkout is a suite that silently stops covering the other three.
_PKG_ROOT = next((c for c in (os.path.join(REPO, "global"),
                              os.path.join(REPO, "utilities"),
                              REPO)
                  if os.path.isdir(os.path.join(c, "execution"))), None)
if _PKG_ROOT is None:
    print(f"FAIL: no execution package found under {REPO} (looked in global/ and utilities/)")
    sys.exit(1)
EXEC_DIR = os.path.join(_PKG_ROOT, "execution")
sys.path.insert(0, _PKG_ROOT)

from execution import settings as S       # noqa: E402
from execution import ssh_mux             # noqa: E402

EXEC = {"name": "test-box", "vendor": "linode", "host": "203.0.113.10",
        "user": "recon", "ssh_key": "~/.ssh/does-not-exist-test-key",
        "workdir": "/home/recon/run"}

_PASS = _FAIL = 0


def check(label, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {label}")
    else:
        _FAIL += 1
        print(f"  FAIL {label}" + (f"\n         {detail}" if detail else ""))


def opts_of(argv_or_str):
    """The -o VALUE pairs out of an argv list or an rsync -e string."""
    toks = argv_or_str.split() if isinstance(argv_or_str, str) else list(argv_or_str)
    return {toks[i + 1] for i, t in enumerate(toks) if t == "-o" and i + 1 < len(toks)}


# ---------------------------------------------------------------- the optimisation itself
def test_mux_options_present():
    print("\n[1] the multiplexing options are actually emitted")
    if not ssh_mux.enabled():
        check("SKIPPED — client too old or SSH_MULTIPLEX=False", True)
        return
    o = opts_of(ssh_mux.ssh_argv(EXEC))
    check("ControlMaster=auto", "ControlMaster=auto" in o, str(o))
    check("a ControlPath is set", any(x.startswith("ControlPath=") for x in o), str(o))
    check("ControlPersist is set", any(x.startswith("ControlPersist=") for x in o), str(o))


def test_control_path_is_hashed_and_short():
    print("\n[2] the socket path can't blow the ~104-byte unix-socket limit")
    if not ssh_mux.enabled():
        check("SKIPPED", True)
        return
    path = [x for x in opts_of(ssh_mux.ssh_argv(EXEC)) if x.startswith("ControlPath=")][0]
    path = path.split("=", 1)[1]
    check("uses the %C hash token, not %h/%r/%p", path.endswith("%C"), path)
    # %C expands to 64 hex chars. Worst case = dir + separator + 64.
    worst = len(ssh_mux.SOCKET_DIR) + 1 + 64
    check(f"worst-case resolved length {worst} < 104", worst < 104, path)


def test_socket_dir_is_private():
    print("\n[3] the socket dir exists and is 0700")
    if not ssh_mux.enabled():
        check("SKIPPED", True)
        return
    ssh_mux.mux_opts()                                  # creates it as a side effect
    check("directory exists", os.path.isdir(ssh_mux.SOCKET_DIR), ssh_mux.SOCKET_DIR)
    mode = os.stat(ssh_mux.SOCKET_DIR).st_mode & 0o777
    check("mode is 0700 (a live authed channel lives here)", mode == 0o700, oct(mode))


# ------------------------------------------------------- what it must NOT have cost us
def test_safety_options_survived():
    print("\n[4] the refactor did not drop a safety option")
    o = opts_of(ssh_mux.ssh_argv(EXEC))
    check("BatchMode=yes (never prompt — unattended dispatch must fail, not hang)",
          "BatchMode=yes" in o, str(o))
    check("StrictHostKeyChecking=accept-new (a CHANGED host key is still refused)",
          "StrictHostKeyChecking=accept-new" in o, str(o))
    check("ConnectTimeout is set", any(x.startswith("ConnectTimeout=") for x in o), str(o))
    check("the identity key is still passed", "-i" in ssh_mux.ssh_argv(EXEC))


def test_off_switch_reverts_exactly():
    print("\n[5] SSH_MULTIPLEX=False reverts to the pre-change invocation, exactly")
    original = getattr(S, "SSH_MULTIPLEX", True)
    try:
        S.SSH_MULTIPLEX = False
        check("enabled() is False", ssh_mux.enabled() is False)
        check("no mux options emitted", ssh_mux.mux_opts() == [], str(ssh_mux.mux_opts()))
        expected = ["ssh", "-i", os.path.expanduser(EXEC["ssh_key"]),
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "ConnectTimeout=15",
                    "recon@203.0.113.10"]
        got = ssh_mux.ssh_argv(EXEC)
        check("argv is byte-identical to the old hand-written form", got == expected,
              f"got      {got}\n         expected {expected}")
    finally:
        S.SSH_MULTIPLEX = original


def test_no_proxy_or_origin_hiding_options():
    print("\n[6] nothing here routes, proxies, or hides an origin")
    joined = " ".join(ssh_mux.ssh_argv(EXEC)) + " " + ssh_mux.rsync_e(EXEC)
    for banned in ("ProxyCommand", "ProxyJump", "-J", "DynamicForward", "-D",
                   "LocalForward", "RemoteForward", "-L", "-R", "-w"):
        check(f"no {banned}", not re.search(rf"(^|\s){re.escape(banned)}(\s|=|$)", joined))


# ------------------------------------------------------------- single definition, no drift
def test_all_transports_agree():
    print("\n[7] ssh, scp and rsync carry the SAME options (one definition, no drift)")
    a, b, c = (opts_of(ssh_mux.ssh_argv(EXEC)), opts_of(ssh_mux.scp_argv(EXEC)),
               opts_of(ssh_mux.rsync_e(EXEC)))
    check("ssh == scp", a == b, f"ssh-only {a - b} | scp-only {b - a}")
    check("ssh == rsync", a == c, f"ssh-only {a - c} | rsync-only {c - a}")


def test_rsync_e_has_no_spaces_inside_a_token():
    print("\n[8] the rsync -e string survives rsync's own word-splitting")
    s = ssh_mux.rsync_e(EXEC)
    check("round-trips through split/join unchanged", " ".join(s.split()) == s, repr(s))
    check("no quoting needed (no token contains a space)",
          all('"' not in t and "'" not in t for t in s.split()), repr(s))


def test_callers_route_through_ssh_mux():
    print("\n[9] every remote helper builds its SSH through ssh_mux — no hand-rolled argv")
    for fn in ("remote_exec.py", "remote_data.py", "remote_monitor.py"):
        src = open(os.path.join(EXEC_DIR, fn), encoding="utf-8").read()
        check(f"{fn} imports ssh_mux", "ssh_mux" in src)
        # A literal ["ssh", ... or ["scp", ... means someone rebuilt the argv by hand and the
        # options can now drift out of sync with the other two callers. That is the exact
        # failure this module was created to prevent, so it is a test, not a comment.
        hand = re.findall(r'\[\s*"(?:ssh|scp)"\s*,', src)
        check(f"{fn} has no hand-built ssh/scp argv", not hand, f"found {len(hand)}")
        inline_e = re.findall(r'"-e"\s*,\s*f?"ssh ', src)
        check(f"{fn} has no inline rsync -e string", not inline_e, f"found {len(inline_e)}")


def test_lifecycle_helpers_are_safe_without_a_box():
    print("\n[10] the lifecycle helpers degrade safely with nothing configured")
    check("is_open() on an unreachable box returns False, does not raise",
          ssh_mux.is_open(EXEC) is False)
    st = ssh_mux.status()
    check("status() returns a list", isinstance(st, list), repr(st)[:120])
    check("close_all() returns a list, does not raise", isinstance(ssh_mux.close_all(), list))


def test_settings_knobs_exist():
    print("\n[11] the off switch and the persist window are real settings")
    check("settings.SSH_MULTIPLEX exists", hasattr(S, "SSH_MULTIPLEX"))
    check("settings.SSH_CONTROL_PERSIST exists", hasattr(S, "SSH_CONTROL_PERSIST"))
    persist = getattr(S, "SSH_CONTROL_PERSIST", "")
    check("persist is a short idle window, not 'yes' (which never self-closes)",
          persist != "yes" and bool(re.fullmatch(r"\d+[smh]?", str(persist))), repr(persist))


def test_cli_runs():
    print("\n[12] `python3 ssh_mux.py` reports state without touching the network")
    r = subprocess.run([sys.executable, os.path.join(EXEC_DIR, "ssh_mux.py")],
                       capture_output=True, text=True, timeout=60)
    check("exits 0", r.returncode == 0, r.stderr[:200])
    check("names the state", "multiplexing" in r.stdout.lower(), r.stdout[:200])


def main():
    print("=" * 78)
    print("test_ssh_mux — connection reuse, and everything it must not have broken")
    print("=" * 78)
    for fn in (test_mux_options_present, test_control_path_is_hashed_and_short,
               test_socket_dir_is_private, test_safety_options_survived,
               test_off_switch_reverts_exactly, test_no_proxy_or_origin_hiding_options,
               test_all_transports_agree, test_rsync_e_has_no_spaces_inside_a_token,
               test_callers_route_through_ssh_mux, test_lifecycle_helpers_are_safe_without_a_box,
               test_settings_knobs_exist, test_cli_runs):
        fn()
    print("\n" + "=" * 78)
    print(f"{_PASS} passed, {_FAIL} failed")
    print("=" * 78)
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
