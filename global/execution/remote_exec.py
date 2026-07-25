"""
remote_exec — run a recon/scan command on a REMOTE executor, results synced back.
================================================================================

Purpose: get heavy tool traffic (esp. bulk DNS) OFF the home residential IP by
running the tool on a separate VPS. The orchestrator (Claude) stays home on its
clean, direct Anthropic connection; ONLY the tool runs remote. This never carries
Anthropic traffic and is never a VPN/proxy for the home box.

STATUS (2026-07-25): VALIDATED end-to-end against the live executor. A command was
dispatched, ran on the box (confirmed by the box's own hostname coming back, not this
machine's), and its output was encrypted, pulled, checksum-verified, decrypted, and purged
remotely, with the ledger reconciling to zero outstanding. The verify-before-purge and
decrypt-before-purge invariants were both exercised by fault injection and hold.
Not yet exercised: a real scanner against a live in-scope asset — only dnsx, httpx and
subfinder are installed on the box (see provision_executor.sh for the rest).

READ THIS FIRST — the thing that actually bites:
    `settings.resolve_mode()` returning "remote" does NOT mean tools are running remotely.
    Nothing routes automatically. Resolving to remote tells you where tools SHOULD run;
    calling run_remote() is what makes it so. A network tool invoked directly through Bash
    runs HERE, on the home IP, no matter what the mode says. (This is exactly the gap found
    on 2026-07-25: the config claimed auto-routing that never existed.)

The framing matters too: this is not a tunnel and not a proxy. We SSH to a machine the
operator owns and run a tool on it, then bring the results back — ordinary sysadmin work.
Nothing here hides an origin or rotates an IP; both are forbidden elsewhere in this
framework and nothing in this module should ever be built toward them.

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


def run_remote(command, engagement, name=None, pull=None, timeout=None, secure_pull=True):
    """Dispatch `command` to a remote executor after LOCAL scope validation, then bring
    any `pull` result files home. Returns a dict.

    secure_pull=True (default) runs the full data lifecycle: encrypt on the box, pull,
    verify the checksum, purge the remote copy, record it in the ledger. Set it False
    only when you deliberately want the remote copy left in place (e.g. a resumable run
    that is not finished) — and remember `remote_data.py sweep` is then how you find it
    again.
    """
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

    # The executor is a SEPARATE machine with its own toolchain — a tool present locally is not
    # necessarily installed there. Without this, a missing remote binary surfaces only as a bare
    # rc=127, which reads like a failed scan rather than a missing prerequisite, and invites a
    # pointless retry. Name it, and say what the box actually has.
    if run.returncode == 127 or "command not found" in (run.stderr or ""):
        try:
            tool = shlex.split(command)[0]
        except ValueError:
            tool = command.split()[0] if command.split() else "?"
        # -1 and a per-dir loop: a bare multi-dir `ls` emits "dir:" headers that pollute the list.
        have = subprocess.run(
            ssh_base + ["for d in /usr/local/bin ~/go/bin ~/.local/bin; do "
                        "[ -d \"$d\" ] && ls -1 \"$d\"; done 2>/dev/null"],
            capture_output=True, text=True).stdout.split()
        have = [t for t in have if not t.endswith((":", ".sh"))]
        result["missing_tool"] = tool
        result["executor_tools"] = sorted(set(have))
        result["reason"] = (
            f"'{tool}' is NOT installed on executor '{e['name']}' ({e['host']}). Execution is remote, "
            f"so the tool must exist THERE, not just locally. Installed there: "
            f"{', '.join(sorted(set(have))) or '(none found)'}. Install it on the box, or run this "
            f"step with EXECUTE_MODE='local' — noting local runs put the traffic on the home IP.")

    # ------------------------------------------------------------------ data lifecycle
    # The executor is a TRANSIENT WORKSPACE, never a data store. Engagement material left
    # on a rented VPS is a disclosure the program never agreed to — so results are encrypted
    # on the box, pulled home, VERIFIED, and only then purged. See remote_data for the
    # reasoning behind each step; the invariant that matters here is that nothing is deleted
    # before its checksum has been confirmed to match.
    if pull:
        try:
            from execution import remote_data as RD
        except ImportError:
            RD = None

        if RD is None or not secure_pull:
            # Plain rsync fallback: retrieves results but leaves the remote copy in place.
            local_dir = os.path.join(BUCKET, "engagements", engagement or "_unfiled",
                                     "02_Reconnaissance", "remote")
            os.makedirs(local_dir, exist_ok=True)
            for f in pull:
                src = f"{dest}:{workdir}/{f}"
                rs = subprocess.run(["rsync", "-az", "-e", f"ssh -i {key}", src, local_dir + "/"],
                                    capture_output=True, text=True)
                if rs.returncode == 0:
                    result["pulled"].append(os.path.join(local_dir, os.path.basename(f)))
            result["lifecycle"] = "plain-rsync (remote copies NOT purged)"
            return result

        remote_paths = [f if f.startswith(("/", "~")) else f"{workdir}/{f}" for f in pull]

        # Encrypt in place first: this covers the window between the tool finishing and the
        # pull completing, and anything stranded by a failed transfer. Best-effort — a box
        # without the public cert yet should still return results rather than lose them.
        try:
            encrypted = RD.encrypt_remote(remote_paths, name=e["name"])
            result["encrypted"] = encrypted
            targets = encrypted
        except Exception as exc:                      # noqa: BLE001 — never lose data to a crypto hiccup
            result["encrypt_error"] = str(exc)
            result["encrypt_hint"] = ("run `remote_data.py setup` to install the public cert on "
                                      "the executor; pulling unencrypted for now.")
            targets = remote_paths

        life = RD.pull(targets, engagement, name=e["name"], purge=True, decrypt=True)
        result["pulled"] = life["pulled"]
        result["verified"] = life["verified"]
        result["decrypted"] = life["decrypted"]
        result["purged"] = life["purged"]
        result["stranded"] = life["stranded"]
        result["lifecycle"] = "encrypt -> pull -> verify -> purge -> ledger"
        if life["stranded"]:
            result["warning"] = (f"{len(life['stranded'])} artifact(s) NOT purged — they remain on "
                                 f"{e['host']}. Run `remote_data.py sweep` to review.")
    return result


if __name__ == "__main__":
    print("remote_exec — status:", "ENABLED" if S.EXECUTE_MODE == "remote" else "disabled (local mode)")
    print(S.summary())
    if S.EXECUTE_MODE != "remote":
        print("\nThis is a disabled scaffold. To use it: provision a VPS per "
              "docs/REMOTE-EXECUTION.md, fill REMOTE_EXECUTORS in settings.py, set "
              "EXECUTE_MODE='remote', then validate with a scoped test command.")
