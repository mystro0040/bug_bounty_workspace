"""
remote_data — engagement-data lifecycle on a remote executor.
================================================================================

The executor is a TRANSIENT WORKSPACE, never a data store. Target responses, host
inventories and findings are engagement material: on a private or NDA program,
leaving them on a rented VPS is a disclosure risk the program never agreed to.

So the rule is: **data lives on the box only as long as the tool needs it.**

    run tool  ->  encrypt output  ->  pull home  ->  VERIFY  ->  purge remote  ->  ledger

Each step exists for a reason:

* **encrypt** — covers the window between a tool finishing and the pull completing,
  and anything that must persist (a long resumable run, a stranded artifact). The box
  holds only the PUBLIC certificate, so it can encrypt but is mathematically unable to
  decrypt. Compromising the executor yields ciphertext. The private key never leaves
  the operator's machine.
* **verify** — checksums are compared before anything is deleted. We never purge data
  we have not provably retrieved. A failed pull leaves the remote copy intact and marks
  the record `stranded` so it is visible rather than silently lost.
* **purge** — `shred` where the filesystem allows it, then unlink.
* **ledger** — a local record of every artifact: where it was, whether it came home,
  whether it was purged. Cleanup is only trustworthy if it is auditable, and "what is
  still sitting on that box?" must be answerable without logging in and guessing.

Encryption is OpenSSL CMS (hybrid RSA + AES-256). Chosen over `age`/`gpg` because
`openssl` is already present on the executor — introducing a new binary would mean a
§2F-TOOLS provenance review for no security gain.

NOT a scope mechanism. Every command still passes the local scope-lock before dispatch
(see remote_exec). This module governs DATA, not authorization.

CLI:
    python3 remote_data.py status                 # keypair + executor + ledger summary
    python3 remote_data.py setup                  # generate keypair, install cert on box
    python3 remote_data.py list                   # what is on the box right now
    python3 remote_data.py sweep                  # reconcile ledger vs box, show stranded
    python3 remote_data.py sweep --purge          # ...and purge everything remaining
"""
import argparse
import datetime
import hashlib
import json
import os
import posixpath
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from execution import settings as S  # noqa: E402

CONF_DIR = os.path.expanduser("~/.config/offsec")
PRIV_KEY = os.path.join(CONF_DIR, "remote-data-key.pem")     # NEVER leaves this machine
PUB_CERT = os.path.join(CONF_DIR, "remote-data-cert.pem")    # copied to the executor
LEDGER = os.path.join(CONF_DIR, "remote_ledger.json")
REMOTE_CERT = "~/.config/offsec/remote-data-cert.pem"

ENC_SUFFIX = ".cms"


class RemoteDataError(RuntimeError):
    pass


# --------------------------------------------------------------------------- utils
def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _executor(name=None):
    name = name or S.DEFAULT_EXECUTOR
    if not S.REMOTE_EXECUTORS:
        raise RemoteDataError("no REMOTE_EXECUTORS configured.")
    for e in S.REMOTE_EXECUTORS:
        if e.get("name") == name or name is None:
            return e
    raise RemoteDataError(f"executor '{name}' not found.")


def _ssh(e):
    return ["ssh", "-i", os.path.expanduser(e["ssh_key"]), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
            f"{e['user']}@{e['host']}"]


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _remote(e, script, timeout=120):
    r = _run(_ssh(e) + [script], timeout=timeout)
    if r.returncode != 0 and not r.stdout:
        raise RemoteDataError(f"remote command failed on {e['name']}: {r.stderr.strip()[:200]}")
    return r.stdout


def _sha256_local(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- ledger
def ledger_load():
    if not os.path.isfile(LEDGER):
        return {"artifacts": []}
    try:
        with open(LEDGER, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"artifacts": []}


def ledger_save(d):
    os.makedirs(CONF_DIR, exist_ok=True)
    tmp = LEDGER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2)
    os.replace(tmp, LEDGER)
    os.chmod(LEDGER, 0o600)


def ledger_record(executor, engagement, remote_path, status, **extra):
    """status: remote | pulled | purged | stranded"""
    d = ledger_load()
    for a in d["artifacts"]:
        if a["executor"] == executor and a["remote_path"] == remote_path:
            a.update(status=status, updated=_now(), **extra)
            ledger_save(d)
            return a
    rec = {"executor": executor, "engagement": engagement, "remote_path": remote_path,
           "status": status, "created": _now(), "updated": _now()}
    rec.update(extra)
    d["artifacts"].append(rec)
    ledger_save(d)
    return rec


def ledger_outstanding(executor=None):
    """Artifacts believed to still be on a box (not purged)."""
    return [a for a in ledger_load()["artifacts"]
            if a["status"] in ("remote", "stranded")
            and (executor is None or a["executor"] == executor)]


# --------------------------------------------------------------------------- keypair
def keypair_exists():
    return os.path.isfile(PRIV_KEY) and os.path.isfile(PUB_CERT)


def setup_encryption(name=None, force=False):
    """Generate the local keypair and install ONLY the public cert on the executor.

    The private key stays here at 0600 and is never transmitted. The box can encrypt
    to us; it cannot read what it encrypted.
    """
    e = _executor(name)
    os.makedirs(CONF_DIR, exist_ok=True)

    if keypair_exists() and not force:
        created = "existing keypair reused"
    else:
        r = _run(["openssl", "req", "-x509", "-newkey", "rsa:4096",
                  "-keyout", PRIV_KEY, "-out", PUB_CERT, "-days", "3650",
                  "-nodes", "-subj", "/CN=offsec-remote-data"])
        if r.returncode != 0:
            raise RemoteDataError(f"keypair generation failed: {r.stderr[:300]}")
        created = "new keypair generated"
    os.chmod(PRIV_KEY, 0o600)

    # push the PUBLIC cert only
    _remote(e, "mkdir -p ~/.config/offsec && chmod 700 ~/.config/offsec")
    r = _run(["scp", "-i", os.path.expanduser(e["ssh_key"]), "-o", "BatchMode=yes",
              "-o", "StrictHostKeyChecking=accept-new", PUB_CERT,
              f"{e['user']}@{e['host']}:{REMOTE_CERT.replace('~/', '')}"])
    if r.returncode != 0:
        # scp with a ~ destination is inconsistent across versions; fall back to a piped write
        with open(PUB_CERT, encoding="utf-8") as fh:
            cert = fh.read()
        _remote(e, f"cat > {REMOTE_CERT} <<'EOF_CERT'\n{cert}\nEOF_CERT")

    have = _remote(e, f"test -s {REMOTE_CERT} && echo OK || echo MISSING").strip()
    if have != "OK":
        raise RemoteDataError("public cert did not land on the executor.")

    # Prove the box cannot decrypt: the private key must not exist there.
    leaked = _remote(e, "ls ~/.config/offsec/ 2>/dev/null").split()
    return {"executor": e["name"], "keypair": created, "private_key": PRIV_KEY,
            "cert_installed": REMOTE_CERT, "remote_files": leaked,
            "private_key_on_box": any("key" in f for f in leaked)}


# --------------------------------------------------------------------------- inventory
def list_remote(name=None, workdir=None):
    """Inventory the executor's workdir: path, size, sha256, encrypted?"""
    e = _executor(name)
    wd = workdir or e.get("workdir", "~/run")
    script = (f"cd {shlex.quote(wd)} 2>/dev/null || exit 0; "
              "find . -type f -printf '%s\\t%P\\n' 2>/dev/null | while IFS=$'\\t' read -r sz p; do "
              "printf '%s\\t%s\\t%s\\n' \"$sz\" \"$(sha256sum \"$p\" | cut -d' ' -f1)\" \"$p\"; done")
    out = _remote(e, script)
    items = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        size, sha, rel = parts
        items.append({"path": posixpath.join(wd, rel), "rel": rel, "size": int(size),
                      "sha256": sha, "encrypted": rel.endswith(ENC_SUFFIX)})
    return {"executor": e["name"], "host": e["host"], "workdir": wd, "files": items}


# --------------------------------------------------------------------------- encrypt
def encrypt_remote(paths, name=None, shred_original=True):
    """CMS-encrypt files in place on the executor, to our public cert.

    Produces <path>.cms and shreds the plaintext. The box cannot reverse this.
    """
    e = _executor(name)
    check = _remote(e, f"test -s {REMOTE_CERT} && echo OK || echo MISSING").strip()
    if check != "OK":
        raise RemoteDataError("no public cert on the executor — run `remote_data.py setup` first.")

    done = []
    for p in paths:
        q = shlex.quote(p)
        enc = shlex.quote(p + ENC_SUFFIX)
        script = (f"test -f {q} || exit 3; "
                  f"openssl cms -encrypt -binary -aes-256-cbc -in {q} -out {enc} "
                  f"-outform DER {REMOTE_CERT} && echo ENC_OK")
        out = _remote(e, script)
        if "ENC_OK" not in out:
            raise RemoteDataError(f"encryption failed for {p}")
        if shred_original:
            _remote(e, f"shred -u {q} 2>/dev/null || rm -f {q}")
        done.append(p + ENC_SUFFIX)
    return done


def decrypt_local(path, out_path=None):
    """Decrypt a pulled .cms artifact with the local private key."""
    if not os.path.isfile(PRIV_KEY):
        raise RemoteDataError(f"private key missing ({PRIV_KEY}); cannot decrypt.")
    out_path = out_path or (path[:-len(ENC_SUFFIX)] if path.endswith(ENC_SUFFIX) else path + ".dec")
    r = _run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
              "-in", path, "-out", out_path, "-inkey", PRIV_KEY])
    if r.returncode != 0:
        raise RemoteDataError(f"decryption failed for {path}: {r.stderr[:200]}")
    return out_path


# --------------------------------------------------------------------------- pull/purge
def _remote_sha(e, path):
    out = _remote(e, f"sha256sum {shlex.quote(path)} 2>/dev/null | cut -d' ' -f1")
    return out.strip() or None


def purge_remote(paths, name=None):
    """Shred-and-unlink specific remote paths. Records purged in the ledger."""
    e = _executor(name)
    purged, failed = [], []
    for p in paths:
        q = shlex.quote(p)
        _remote(e, f"shred -u {q} 2>/dev/null || rm -f {q}")
        still = _remote(e, f"test -e {q} && echo PRESENT || echo GONE").strip()
        if still == "GONE":
            purged.append(p)
            ledger_record(e["name"], None, p, "purged")
        else:
            failed.append(p)
    return {"purged": purged, "failed": failed}


def pull(files, engagement, name=None, local_dir=None, purge=True, decrypt=True):
    """Pull remote artifacts home, VERIFY, then purge the remote copy.

    Nothing is deleted until the local copy's checksum matches the remote one. A
    mismatch or transfer failure leaves the remote file in place and marks it
    `stranded` so `sweep` will surface it.
    """
    e = _executor(name)
    wd = e.get("workdir", "~/run")
    bucket = os.path.expanduser("~/Workspace/buckets/bug-bounty-workspace-bucket")
    local_dir = local_dir or os.path.join(bucket, "engagements", engagement or "_unfiled",
                                          "02_Reconnaissance", "remote")
    os.makedirs(local_dir, exist_ok=True)

    out = {"pulled": [], "verified": [], "purged": [], "stranded": [], "decrypted": []}
    for f in files:
        rpath = f if f.startswith("/") or f.startswith("~") else posixpath.join(wd, f)
        rsha = _remote_sha(e, rpath)
        if not rsha:
            out["stranded"].append({"path": rpath, "reason": "not found on executor"})
            continue

        ledger_record(e["name"], engagement, rpath, "remote", sha256=rsha)
        dest = os.path.join(local_dir, posixpath.basename(rpath))
        rs = _run(["rsync", "-az", "-e", f"ssh -i {os.path.expanduser(e['ssh_key'])} -o BatchMode=yes",
                   f"{e['user']}@{e['host']}:{rpath}", dest])
        if rs.returncode != 0 or not os.path.isfile(dest):
            out["stranded"].append({"path": rpath, "reason": f"rsync failed: {rs.stderr[:120]}"})
            ledger_record(e["name"], engagement, rpath, "stranded", sha256=rsha,
                          reason="rsync failed")
            continue
        out["pulled"].append(dest)

        # VERIFY before any deletion
        if _sha256_local(dest) != rsha:
            out["stranded"].append({"path": rpath, "reason": "checksum mismatch — NOT purged"})
            ledger_record(e["name"], engagement, rpath, "stranded", sha256=rsha,
                          reason="checksum mismatch")
            continue
        out["verified"].append(dest)
        ledger_record(e["name"], engagement, rpath, "pulled", sha256=rsha, local_path=dest)

        # A matching checksum proves the BYTES arrived — not that they are RECOVERABLE.
        # If the ciphertext will not open (wrong/rotated/missing private key), purging the
        # remote copy destroys the only readable original and the loss is permanent. So a
        # failed decrypt is treated exactly like a failed verify: keep the remote copy.
        recoverable = True
        if decrypt and dest.endswith(ENC_SUFFIX):
            try:
                out["decrypted"].append(decrypt_local(dest))
            except RemoteDataError as exc:
                recoverable = False
                out["stranded"].append({"path": rpath,
                                        "reason": f"local decrypt failed — NOT purged: {exc}"})
                ledger_record(e["name"], engagement, rpath, "stranded", sha256=rsha,
                              reason="local decrypt failed")

        if purge and recoverable:
            res = purge_remote([rpath], name=e["name"])
            out["purged"].extend(res["purged"])
            for bad in res["failed"]:
                out["stranded"].append({"path": bad, "reason": "purge failed"})
    return out


# --------------------------------------------------------------------------- sweep
def sweep(name=None, purge=False, workdir=None):
    """Reconcile the ledger against what is actually on the box.

    Answers the only question that matters for cleanup: what is still sitting there?
    Anything present on the executor is reported; `--purge` removes it (after which
    nothing engagement-related should remain).
    """
    e = _executor(name)
    inv = list_remote(name=e["name"], workdir=workdir)
    on_box = inv["files"]
    known = {a["remote_path"]: a for a in ledger_load()["artifacts"] if a["executor"] == e["name"]}

    report = {"executor": e["name"], "host": e["host"], "workdir": inv["workdir"],
              "on_box": len(on_box), "plaintext_on_box": [], "untracked": [],
              "believed_purged_but_present": [], "outstanding_in_ledger": [], "purged": []}

    for f in on_box:
        if not f["encrypted"]:
            report["plaintext_on_box"].append(f["rel"])
        rec = known.get(f["path"])
        if rec is None:
            report["untracked"].append(f["rel"])
        elif rec["status"] == "purged":
            report["believed_purged_but_present"].append(f["rel"])

    present = {f["path"] for f in on_box}
    for a in ledger_outstanding(e["name"]):
        if a["remote_path"] not in present:
            a = dict(a)
            a["note"] = "ledger says present, box says gone — reconciled"
            ledger_record(e["name"], a.get("engagement"), a["remote_path"], "purged")
        else:
            report["outstanding_in_ledger"].append(a["remote_path"])

    if purge and on_box:
        res = purge_remote([f["path"] for f in on_box], name=e["name"])
        report["purged"] = res["purged"]
        report["purge_failed"] = res["failed"]
    return report


# --------------------------------------------------------------------------- status
def status(name=None):
    try:
        e = _executor(name)
    except RemoteDataError as exc:
        return {"error": str(exc)}
    led = ledger_load()["artifacts"]
    return {
        "execute_mode": S.EXECUTE_MODE,
        "resolves_to": S.resolve_mode(),
        "executor": e["name"], "host": e["host"], "vendor": e.get("vendor"),
        "keypair_present": keypair_exists(),
        "private_key": PRIV_KEY if os.path.isfile(PRIV_KEY) else None,
        "ledger_total": len(led),
        "outstanding": len(ledger_outstanding(e["name"])),
        "by_status": {s: sum(1 for a in led if a["status"] == s)
                      for s in ("remote", "pulled", "purged", "stranded")},
    }


def _main():
    ap = argparse.ArgumentParser(description="Remote engagement-data lifecycle.")
    ap.add_argument("action", choices=["status", "setup", "list", "sweep", "pull", "purge"])
    ap.add_argument("--executor")
    ap.add_argument("--engagement")
    ap.add_argument("--files", nargs="*", default=[])
    ap.add_argument("--purge", action="store_true", help="sweep: also delete what remains")
    ap.add_argument("--force", action="store_true", help="setup: regenerate the keypair")
    ap.add_argument("--no-purge", action="store_true", help="pull: keep the remote copy")
    a = ap.parse_args()

    try:
        if a.action == "status":
            out = status(a.executor)
        elif a.action == "setup":
            out = setup_encryption(a.executor, force=a.force)
        elif a.action == "list":
            out = list_remote(a.executor)
        elif a.action == "sweep":
            out = sweep(a.executor, purge=a.purge)
        elif a.action == "pull":
            out = pull(a.files, a.engagement, name=a.executor, purge=not a.no_purge)
        elif a.action == "purge":
            out = purge_remote(a.files, name=a.executor)
    except (RemoteDataError, PermissionError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
