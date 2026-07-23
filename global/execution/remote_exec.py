"""
remote_exec — run a recon/scan command on a REMOTE executor, results synced back.
================================================================================

Purpose: get heavy tool traffic (esp. bulk DNS) OFF the home residential IP by
running the tool on a separate VPS. The orchestrator (Claude) stays home on its
clean, direct Anthropic connection; ONLY the tool runs remote. This never carries
Anthropic traffic and is never a VPN/proxy for the home box.

STATUS: SCAFFOLD. Disabled by default (settings.EXECUTE_MODE="local"). The SSH/rsync
plumbing is written and self-contained, but it has NOT been validated end-to-end
against a live VPS yet — do that once a box is provisioned (see docs/REMOTE-EXECUTION.md
and the Desktop hosting note). Until then it refuses to run.

TWO SAFETY INVARIANTS, enforced here:
  1. SCOPE STILL APPLIES. Every command is validated against the LOCAL engagement
     scope-lock BEFORE it is sent. Offloading to a VPS must never become a way around
     the enforce_scope wall — so we check here, before dispatch.
  2. ANTHROPIC NEVER TRAVERSES THIS. This module only opens an SSH channel from home
     to the executor to run TOOLS. Claude's API traffic does not go through it.

Usage (only when settings.EXECUTE_MODE == "remote"):
    from execution.remote_exec import run_remote
    result = run_remote("dnsx -l cand.txt -r resolvers.txt -rl 6 -t 25 -o out.txt",
                        engagement="programs/hackerone/bounty/remitly",
                        pull=["out.txt"])
"""
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from execution import settings as S  # noqa: E402

BUCKET = os.path.expanduser("~/Workspace/buckets/bug-bounty-workspace-bucket")


class RemoteError(RuntimeError):
    pass


def _executor(name=None):
    name = name or S.DEFAULT_EXECUTOR
    if not S.REMOTE_EXECUTORS:
        raise RemoteError("no REMOTE_EXECUTORS configured in settings.py (still local-only).")
    if name is None:
        raise RemoteError("no DEFAULT_EXECUTOR set and no executor name given.")
    for e in S.REMOTE_EXECUTORS:
        if e.get("name") == name:
            return e
    raise RemoteError(f"executor '{name}' not found in REMOTE_EXECUTORS.")


def _scope_ok(command, engagement):
    """Validate the command against the LOCAL scope-lock via the same enforce_scope
    hook the interactive agent uses — so a remote command is walled identically to a
    typed one. Fail CLOSED: if we cannot prove it is in scope, we refuse."""
    hook = os.path.join(BUCKET, ".claude", "hooks", "enforce_scope.py")
    if not os.path.isfile(hook):
        raise RemoteError(f"scope hook not found ({hook}); refusing to dispatch un-vetted command.")
    import json
    payload = json.dumps({"tool_name": "Bash",
                          "tool_input": {"command": command},
                          "cwd": BUCKET})
    env = dict(os.environ, AO_ENGAGEMENT=engagement or "")
    r = subprocess.run([sys.executable, hook], input=payload,
                       capture_output=True, text=True, env=env)
    out = (r.stdout or "").strip()
    if not out:
        return True, "allow (hook returned no objection)"
    try:
        d = json.loads(out)
        decision = d["hookSpecificOutput"]["permissionDecision"]
        reason = d["hookSpecificOutput"].get("permissionDecisionReason", "")
    except (ValueError, KeyError):
        raise RemoteError(f"could not parse scope-hook output; refusing. raw: {out[:200]}")
    return decision == "allow", reason


def run_remote(command, engagement, name=None, pull=None, timeout=None):
    """Dispatch `command` to a remote executor after LOCAL scope validation, then
    rsync any `pull` result files back into the engagement folder. Returns a dict."""
    if S.resolve_mode() != "remote":
        raise RemoteError("execution resolves to 'local' — refusing remote dispatch. Configure a "
                          "REMOTE_EXECUTORS entry on a CLEARED vendor (or set EXECUTE_MODE='remote').")

    e = _executor(name)

    # Vendor gate: the box's provider AUP must be CLEARED (vendors.py status='allowed').
    vendor = e.get("vendor")
    if not vendor:
        raise RemoteError(f"executor '{e.get('name')}' has no 'vendor' — cannot verify its AUP. Refusing.")
    from execution import vendors
    vendors.assert_usable(vendor)          # raises PermissionError if not cleared

    ok, reason = _scope_ok(command, engagement)
    if not ok:
        raise RemoteError(f"SCOPE DENIED locally — not dispatching remotely. {reason}")
    key = os.path.expanduser(e["ssh_key"])
    dest = f"{e['user']}@{e['host']}"
    workdir = e.get("workdir", "~/run")
    ssh_base = ["ssh", "-i", key, "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", dest]

    wrapped = f"mkdir -p {shlex.quote(workdir)} && cd {shlex.quote(workdir)} && "
    to = timeout or S.UNATTENDED_TOOL_TIMEOUT
    wrapped += f"timeout {shlex.quote(to)} bash -lc {shlex.quote(command)}"

    run = subprocess.run(ssh_base + [wrapped], capture_output=True, text=True)
    result = {"executor": e["name"], "host": e["host"], "rc": run.returncode,
              "stdout": run.stdout, "stderr": run.stderr, "pulled": []}

    # rsync result files back into the engagement's recon area
    if pull:
        local_dir = os.path.join(BUCKET, "engagements", engagement, "02_Reconnaissance", "remote")
        os.makedirs(local_dir, exist_ok=True)
        for f in pull:
            src = f"{dest}:{workdir}/{f}"
            rs = subprocess.run(["rsync", "-az", "-e", f"ssh -i {key}", src, local_dir + "/"],
                                capture_output=True, text=True)
            if rs.returncode == 0:
                result["pulled"].append(os.path.join(local_dir, os.path.basename(f)))
    return result


if __name__ == "__main__":
    print("remote_exec — status:", "ENABLED" if S.EXECUTE_MODE == "remote" else "disabled (local mode)")
    print(S.summary())
    if S.EXECUTE_MODE != "remote":
        print("\nThis is a disabled scaffold. To use it: provision a VPS per "
              "docs/REMOTE-EXECUTION.md, fill REMOTE_EXECUTORS in settings.py, set "
              "EXECUTE_MODE='remote', then validate with a scoped test command.")
