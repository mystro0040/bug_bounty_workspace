"""
remote_monitor — orchestrator-side watch of each remote executor (security + resources).
================================================================================

The §2F RAM guardrail watches the LOCAL machine. When tools run on a VPS, the orchestrator must
watch the REMOTE box too — its RAM/CPU/load (so two agents don't hammer it into swap) AND its login
activity (so an intruder is noticed). This SSHes to each configured executor, runs the two on-box
reporters (`box_health.sh`, `login_watch.sh`), collects ALERT lines, and surfaces them THREE ways:
  1. returns/prints them (in-session)
  2. writes a desktop status file (~/Desktop/temp/REMOTE-BOX-STATUS.md)
  3. (web app reads the same status file / hub when wired)

Run periodically:  python3 remote_monitor.py         # check all executors
                   python3 remote_monitor.py --quiet  # only print if something is wrong
Exit code: 0 = all OK, 1 = alert(s) found, 2 = a box was unreachable.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from execution import settings as S  # noqa: E402

STATUS_FILE = os.path.expanduser("~/Desktop/temp/REMOTE-BOX-STATUS.md")


def _ssh(executor, remote_cmd):
    key = os.path.expanduser(executor["ssh_key"])
    dest = f"{executor['user']}@{executor['host']}"
    r = subprocess.run(
        ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", dest, remote_cmd],
        capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def check_executor(executor):
    """Return dict: {name, reachable, alerts:[...], health:str, logins:str}."""
    name = executor.get("name", "?")
    rc, out, err = _ssh(executor, "box_health.sh; echo '<<<SPLIT>>>'; sudo -n login_watch.sh")
    if rc != 0 and not out:
        return {"name": name, "reachable": False, "alerts": [f"UNREACHABLE: {err.strip()[:120]}"],
                "health": "", "logins": ""}
    health, _, logins = out.partition("<<<SPLIT>>>")
    alerts = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("ALERT")]
    return {"name": name, "reachable": True, "alerts": alerts,
            "health": health.strip(), "logins": logins.strip()}


def write_status(results):
    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    any_alert = any(r["alerts"] for r in results)
    lines = ["# 🖥️ Remote box status", ""]
    lines.append("## ⚠️ ALERTS PRESENT" if any_alert else "## ✅ All remote boxes healthy")
    lines.append("")
    for r in results:
        lines.append(f"### {r['name']} — {'reachable' if r['reachable'] else '❌ UNREACHABLE'}")
        if r["alerts"]:
            for a in r["alerts"]:
                lines.append(f"- 🚨 {a}")
        else:
            lines.append("- ok, no alerts")
        if r["health"]:
            lines.append("\n<details><summary>health</summary>\n\n```\n" + r["health"] + "\n```\n</details>")
        if r["logins"]:
            lines.append("\n<details><summary>logins</summary>\n\n```\n" + r["logins"] + "\n```\n</details>")
        lines.append("")
    with open(STATUS_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv):
    quiet = "--quiet" in argv[1:]
    execs = S.REMOTE_EXECUTORS
    if not execs:
        if not quiet:
            print("no remote executors configured (local mode).")
        return 0
    results = [check_executor(e) for e in execs]
    write_status(results)
    unreachable = any(not r["reachable"] for r in results)
    alerts = [(r["name"], a) for r in results for a in r["alerts"]]
    if alerts:
        print("🚨 REMOTE BOX ALERTS:")
        for name, a in alerts:
            print(f"  [{name}] {a}")
        print(f"(details written to {STATUS_FILE})")
        return 2 if unreachable else 1
    if not quiet:
        for r in results:
            print(f"✅ {r['name']}: healthy, no anomalous logins.")
        print(f"(status written to {STATUS_FILE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
