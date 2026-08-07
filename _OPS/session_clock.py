#!/usr/bin/env python3
"""How long has this testing session been running? A runaway guard, not a stop button.

THE OPERATOR'S REASONING, kept because it is the correct framing:
"the most important thing is that you keep testing if there are things to test" — the ceiling
exists only so an unattended session cannot grind forever while nobody is watching. It is a
SAFETY precaution against a runaway, never a reason to stop while the operator is present and
there is permitted surface left.

So this reports. It does not deny, and nothing should wire it to deny.

  python3 _OPS/session_clock.py start     # stamp the beginning of testing
  python3 _OPS/session_clock.py check     # elapsed, and whether the ceiling is passed
"""
import datetime
import os
import sys

OPS = os.path.dirname(os.path.abspath(__file__))
STAMP = os.path.join(OPS, ".session-start")
CEILING_HOURS = 4.0


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def start(when=None):
    t = when or _now()
    with open(STAMP, "w", encoding="utf-8") as fh:
        fh.write(t.isoformat())
    print("session start stamped:", t.isoformat())


def check():
    if not os.path.exists(STAMP):
        print("[?] no session start stamped. Run `session_clock.py start` when testing begins.")
        return 0
    try:
        t0 = datetime.datetime.fromisoformat(open(STAMP, encoding="utf-8").read().strip())
    except Exception:                                             # noqa: BLE001
        print("[?] session stamp unreadable; treating as unknown.")
        return 0
    hrs = (_now() - t0).total_seconds() / 3600.0
    print("testing started : %s" % t0.isoformat(timespec="minutes"))
    print("elapsed         : %.1f hours" % hrs)
    if hrs >= CEILING_HOURS:
        print("ceiling         : %.0fh PASSED — this is the runaway guard, not an instruction."
              % CEILING_HOURS)
        print("                  If the operator is present and there is permitted surface left,")
        print("                  keep testing. If nobody is watching, this is the point to stop")
        print("                  cleanly, write the session log, and sweep the executor.")
    else:
        print("ceiling         : %.0fh (%.1f hours to go) — keep testing."
              % (CEILING_HOURS, CEILING_HOURS - hrs))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "start":
        when = None
        if len(sys.argv) > 2:
            when = datetime.datetime.fromisoformat(sys.argv[2])
        start(when)
        return 0
    return check()


if __name__ == "__main__":
    sys.exit(main())
