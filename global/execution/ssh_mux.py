"""
ssh_mux — ONE place that builds the SSH invocation every remote helper uses.
================================================================================

Why this exists
---------------
A single `run_remote()` call with one input file and one result file opened THIRTEEN
separate SSH connections: 3 to push the input, 1 to run the command, 3 to encrypt on
the box, 4 to pull and verify the result, 2 to purge the input. Thirteen TCP handshakes
and thirteen public-key authentications to do one job.

OpenSSH already solves this. `ControlMaster=auto` opens ONE connection and lets every
later ssh/scp/rsync to the same destination ride it as a new *channel* inside the
existing session. Thirteen handshakes become one. This is a stock feature — no daemon,
no protocol, no custom transport.

What this does NOT change — read this before touching anything here
-------------------------------------------------------------------
Multiplexing is a TRANSPORT optimisation. It is invisible above the socket:

  * SCOPE. `run_remote()` validates every command against the local scope-lock BEFORE
    it opens any connection. Reusing a connection cannot reach a host the wall denied,
    because the wall runs first and the command never gets built. Nothing here is a
    dispatch path.
  * RATE. Rate limits live in the command string (`-rl 5`) and in the rate ceiling the
    hook enforces. A connection is not a request. Sharing one TCP session changes the
    number of SSH handshakes, never the number of packets a tool sends at a target.
  * ATTRIBUTION. The identifying header is part of the command the tool runs. Untouched.
  * ORIGIN. Same key, same user, same box, same IP. This is not a tunnel, not a proxy,
    and it hides nothing — it is one authenticated session to a machine the operator
    owns instead of thirteen identical ones.
  * ERROR REPORTING. Each channel is an independent session carrying its own exit
    status. `ssh` returns the remote command's exit code over a multiplexed connection
    exactly as it does over a dedicated one — a crashed tool still comes back as its
    real rc, and the rc=127 missing-binary detection in remote_exec still fires. This
    is verified by testing/test_ssh_mux.py, not assumed.

The one genuinely new failure mode
----------------------------------
If the MASTER connection dies, every channel riding it dies with it. That is not worse
than today: today a dropped TCP kills the one command it was carrying. What changes is
that a drop during a multi-step lifecycle can now take several steps at once instead of
one — which surfaces as a failed step with a real error, exactly as it would have, and
the lifecycle's own invariants (verify-before-purge) still hold because they are checked
per step and fail closed.

A stale socket — a control file left behind by a master that died — is handled by
`ControlMaster=auto`, which falls back to opening a fresh connection. Verified by
deliberately planting a dead socket in the test suite, not taken on faith.

Turning it off
--------------
`settings.SSH_MULTIPLEX = False` reverts to exactly the previous behaviour: one fresh
connection per operation. Nothing else in the framework needs to change.

Leaving nothing running (§2F-STOP)
----------------------------------
A persistent master is a background `ssh` process on THIS machine holding an open
connection to the executor. It self-reaps after `SSH_CONTROL_PERSIST` idle, and
`remote_data.py disconnect` (or `ssh_mux.close_all()`) closes it immediately. Check what
is open with `ssh_mux.status()`. A stop is not clean while a master is still up.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from execution import settings as S  # noqa: E402

# The control sockets live under the operator's own ~/.ssh, mode 0700.
#
# Security note, stated rather than left implicit: an open control socket is a LIVE
# AUTHENTICATED CHANNEL to the executor. Anything running as this local user can send a
# command down it without holding the private key. That is not a new exposure — the same
# local user already has the passphrase-less key sitting next to it — but it is a real
# property, so the socket dir is 0700 and the masters are short-lived by default.
SOCKET_DIR = os.path.expanduser("~/.ssh/cm-offsec")

# %C is a hash of (local host, remote host, port, user). Using it rather than
# %r@%h:%p keeps the path a fixed, short length: a unix socket path is capped at
# ~104 bytes and a long hostname silently pushes a %h-style path over that limit,
# which fails as a confusing "cannot bind" rather than as "your path is too long".
_CONTROL_PATH = os.path.join(SOCKET_DIR, "%C")


def enabled():
    """Multiplexing is opt-out via settings, and off entirely if the OpenSSH client is
    too old for %C (6.7+). Fail SOFT here, not closed: this is an optimisation, so an
    old client should mean 'run like we did last week', never 'refuse to dispatch'."""
    if not getattr(S, "SSH_MULTIPLEX", True):
        return False
    return _client_supports_control_path_hash()


_SUPPORT_CACHE = {}


def _client_supports_control_path_hash():
    if "ok" in _SUPPORT_CACHE:
        return _SUPPORT_CACHE["ok"]
    try:
        r = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10)
        banner = (r.stderr or r.stdout or "")          # ssh -V prints to stderr
        # e.g. "OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.16"
        ver = banner.split("OpenSSH_", 1)[-1].split(",")[0].split("p")[0].split(" ")[0]
        major, _, minor = ver.partition(".")
        ok = (int(major), int(minor or 0)) >= (6, 7)
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        ok = False
    _SUPPORT_CACHE["ok"] = ok
    return ok


def _ensure_socket_dir():
    """ssh will not create the directory for a ControlPath; a missing one fails the
    connection instead of falling back, so it is created here before every use."""
    os.makedirs(SOCKET_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(SOCKET_DIR, 0o700)                    # tighten a pre-existing loose dir
    except OSError:
        pass


def mux_opts():
    """The multiplexing options alone, as a flat list. Empty when disabled."""
    if not enabled():
        return []
    _ensure_socket_dir()
    persist = getattr(S, "SSH_CONTROL_PERSIST", "60s")
    return ["-o", "ControlMaster=auto",
            "-o", f"ControlPath={_CONTROL_PATH}",
            "-o", f"ControlPersist={persist}"]


def base_opts(connect_timeout=15):
    """Every SSH option this framework uses, in one list, mux included.

    BatchMode: never prompt — an unattended dispatch must fail, not hang on a password.
    StrictHostKeyChecking=accept-new: pin on first sight, refuse a CHANGED key.
    """
    return ["-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={connect_timeout}"] + mux_opts()


def dest(executor):
    return f"{executor['user']}@{executor['host']}"


def ssh_argv(executor, connect_timeout=15):
    """Full `ssh` argv up to (but not including) the remote command."""
    return (["ssh", "-i", os.path.expanduser(executor["ssh_key"])]
            + base_opts(connect_timeout) + [dest(executor)])


def scp_argv(executor, connect_timeout=15):
    """Full `scp` argv up to (but not including) src/dst. scp speaks the same options
    and rides the same master, so a file copy costs a channel, not a handshake."""
    return (["scp", "-i", os.path.expanduser(executor["ssh_key"])]
            + base_opts(connect_timeout))


def rsync_e(executor, connect_timeout=15):
    """The value for `rsync -e`. rsync word-splits this itself, so it must contain no
    spaces inside any single argument — the socket dir has none by construction."""
    parts = ["ssh", "-i", os.path.expanduser(executor["ssh_key"])] + base_opts(connect_timeout)
    return " ".join(parts)


# --------------------------------------------------------------------- lifecycle


def _control_cmd(executor, verb):
    argv = ["ssh", "-i", os.path.expanduser(executor["ssh_key"])]
    argv += ["-o", f"ControlPath={_CONTROL_PATH}", "-O", verb, dest(executor)]
    return subprocess.run(argv, capture_output=True, text=True, timeout=20)


def is_open(executor):
    """True when a master is currently up for this executor."""
    if not enabled():
        return False
    try:
        return _control_cmd(executor, "check").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def close(executor):
    """Close the master for one executor now, rather than waiting for ControlPersist.
    Returns True if a master was open and is now closed."""
    if not enabled() or not is_open(executor):
        return False
    try:
        return _control_cmd(executor, "exit").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def other_clients(exclude_pid=None):
    """PIDs of OTHER processes currently riding the shared master.

    The master is shared by every process on this machine. Counting who is attached is what makes
    it safe to close — see close_all().

    Identified from /proc rather than by parsing `ps`: a client is an ssh process whose command
    line references the control socket directory and which is not itself the master (the master
    carries "[mux]").
    """
    me = exclude_pid or os.getpid()
    found = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return found
    for pid in pids:
        if int(pid) in (me, os.getppid()):
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if SOCKET_DIR in cmd and "[mux]" not in cmd and cmd.strip().startswith(("ssh", "/usr/bin/ssh")):
            found.append(int(pid))
    return found


def close_all(force=False):
    """Close every open master. Part of a clean stop (§2F-STOP).

    REFUSES BY DEFAULT WHEN OTHER WORK IS RIDING THE CONNECTION, and this is not caution for its
    own sake — it happened. On 2026-07-28 a two-hour DNS brute-force lost 5,000 names because an
    ad-hoc probe script finished and called close_all(); the `ssh -O exit` tore down the master and
    every channel on it, and the running job saw rc=255 on both chunks. Nothing was wrong with the
    job, the targets, or the network.

    That is the failure mode this module's own docstring warns about — "if the MASTER connection
    dies, every channel riding it dies with it" — reached by the most ordinary route imaginable:
    two things using one connection, and the one that finished first tidying up after itself.

    Returns {"closed": [...], "refused": [...], "other_clients": [pids]}.
    """
    others = other_clients()
    if others and not force:
        return {"closed": [], "refused": [e.get("name") for e in
                                          (getattr(S, "REMOTE_EXECUTORS", []) or [])],
                "other_clients": others,
                "reason": (f"{len(others)} other process(es) are using the shared SSH connection "
                           f"(pids {others}). Closing it would kill their in-flight commands. "
                           f"Left open — it self-closes after {getattr(S, 'SSH_CONTROL_PERSIST', '60s')} "
                           f"idle anyway. Pass force=True only when you have confirmed nothing "
                           f"else is running.")}
    closed = []
    for e in getattr(S, "REMOTE_EXECUTORS", []) or []:
        try:
            if close(e):
                closed.append(e.get("name"))
        except KeyError:                               # a malformed executor entry
            continue
    return {"closed": closed, "refused": [], "other_clients": others}


def status():
    """Which executors currently have an open master. For a stop check."""
    out = []
    for e in getattr(S, "REMOTE_EXECUTORS", []) or []:
        try:
            out.append({"name": e.get("name"), "open": is_open(e)})
        except KeyError:
            continue
    return out


if __name__ == "__main__":
    print(f"ssh multiplexing: {'ENABLED' if enabled() else 'DISABLED'}")
    if not enabled():
        why = ("settings.SSH_MULTIPLEX is False" if not getattr(S, "SSH_MULTIPLEX", True)
               else "the OpenSSH client is older than 6.7 (no ControlPath %C)")
        print(f"  reason: {why} — every operation opens its own connection, as before.")
    else:
        print(f"  socket dir : {SOCKET_DIR}")
        print(f"  persist    : {getattr(S, 'SSH_CONTROL_PERSIST', '60s')} idle, then self-closes")
    st = status()
    if not st:
        print("  executors  : none configured")
    for row in st:
        print(f"  {row['name']}: {'OPEN (a connection is held)' if row['open'] else 'closed'}")
    if len(sys.argv) > 1 and sys.argv[1] == "disconnect":
        r = close_all(force="--force" in sys.argv)
        if r.get("refused"):
            print("REFUSED:", r["reason"])
        else:
            print("closed:", ", ".join(r["closed"]) or "(nothing was open)")
