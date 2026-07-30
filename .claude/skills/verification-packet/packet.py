#!/usr/bin/env python3
"""
packet.py — scaffold an operator verification packet, and PROVE the public half is anonymised.

    python3 packet.py new   <slug> --engagement <eng>   scaffold the directory + templates
    python3 packet.py check <slug> [--engagement <eng>] verify public/ leaks nothing
    python3 packet.py list                              every packet and its check status

WHY THE CHECK EXISTS
    A packet has two halves that must not mix: `public/` is written to be handed to an outside
    AI or pasted anywhere, `private/` names the real program and hosts. Keeping them apart by
    remembering to is not a mechanism — it is an intention, and this workspace has a long record
    of intentions that turned out to enforce nothing.

    So `check` derives the forbidden terms from the engagement's OWN scope-lock — the hostnames
    and wildcards it is actually authorised against, the program slug, the platform, and the
    operator handle — and greps `public/` for them. Nothing is hardcoded, so a new engagement is
    covered the day it is compiled.

WHY NOT CALLED "verify"
    `findings_store.py verify` already means "re-hash both copies and prove nothing rotted," and
    `scope_compiler.py verify` means "are the compiled artifacts self-consistent." A third
    meaning for the same word is how a checker ends up being run for the wrong reason.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
ENG_ROOT = os.path.join(WORKSPACE, "engagements")
PACKET_ROOT = os.path.expanduser("~/Desktop/temp/verify-findings")
IDENTITY = os.path.join(WORKSPACE, "global", "operator-identity.md")

# Third-party platforms. Naming one is not disclosure on its own — millions of sites use them —
# but platform + bug class together narrows the target, so these WARN rather than block and the
# operator decides.
PLATFORM_HINTS = {"firebase", "vercel", "netlify", "heroku", "cloudfront", "fastly",
                  "wordpress", "shopify", "zendesk", "auth0", "okta", "azure", "cloudflare"}

# Words too short or too common to match on without drowning the result in false positives.
_STOP = {"com", "net", "org", "www", "api", "app", "dev", "web", "the", "and", "inc", "co",
         "io", "ai", "uk", "de", "nl", "cn", "tw", "me", "sh", "js", "id"}


def _identity_handles():
    out = set()
    if os.path.isfile(IDENTITY):
        body = open(IDENTITY, encoding="utf-8", errors="replace").read()
        out |= set(re.findall(r"`([A-Za-z0-9_.-]{4,})`", body))
    return {h.lower() for h in out if h.lower() not in _STOP}


def forbidden_terms(engagement):
    """Everything that would identify the target, derived from what the engagement actually is.

    Hostnames and wildcards come from the compiled scope-lock — the same file the wall enforces —
    so this can never drift from the real asset list. Each hostname also contributes its
    distinctive labels, because `acme` alone identifies `acme.com` just as well.
    """
    terms = set()
    d = os.path.join(ENG_ROOT, engagement)
    lock = os.path.join(d, ".scope_lock", "enforcement.json")
    if os.path.isfile(lock):
        a = (json.load(open(lock, encoding="utf-8")) or {}).get("assets") or {}
        for host in list(a.get("hosts") or []) + list(a.get("wildcards") or []):
            h = host.lstrip("*.").lower()
            terms.add(h)
            for label in h.split("."):
                if len(label) >= 4 and label not in _STOP:
                    terms.add(label)
    # Program slug and platform from the engagement path: programs/<platform>/<tier>/<slug>
    for part in engagement.split("/"):
        p = part.lower()
        if p not in {"programs", "labs", "bounty", "no-bounty"} and len(p) >= 4:
            terms.add(p)
            for chunk in re.split(r"[-_]", p):
                if len(chunk) >= 4 and chunk not in _STOP:
                    terms.add(chunk)
    terms |= _identity_handles()
    return {t for t in terms if t not in _STOP}


def scan(path, terms):
    """Word-boundary matches only.

    Substring matching produced a false positive on the first real run — "exact" inside
    "exactly" — and a checker that cries wolf is one that gets ignored, which is worse than not
    having it.
    """
    hits = []
    pattern = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(sorted(map(re.escape, terms), key=len,
                                                                  reverse=True)) + r")(?![A-Za-z0-9])",
                         re.I) if terms else None
    plat = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(sorted(PLATFORM_HINTS)) + r")(?![A-Za-z0-9])", re.I)
    for dirpath, _, files in os.walk(path):
        for fn in sorted(files):
            fp = os.path.join(dirpath, fn)
            try:
                text = open(fp, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if pattern:
                    for m in pattern.finditer(line):
                        hits.append(("LEAK", os.path.relpath(fp, path), n, m.group(1), line.strip()[:90]))
                for m in plat.finditer(line):
                    hits.append(("platform", os.path.relpath(fp, path), n, m.group(1), line.strip()[:90]))
    return hits


def check(slug, engagement):
    d = os.path.join(PACKET_ROOT, slug)
    pub = os.path.join(d, "public")
    if not os.path.isdir(pub):
        print(f"no public/ directory at {pub}")
        return 2
    if not engagement:
        meta = os.path.join(d, ".engagement")
        engagement = open(meta).read().strip() if os.path.isfile(meta) else None
    if not engagement:
        print("cannot check: no engagement recorded. Re-run with --engagement, or create the\n"
              "packet with `new` so the engagement is written to .engagement at scaffold time.\n"
              "Refusing to pass a packet whose anonymisation cannot be checked against anything.")
        return 2

    terms = forbidden_terms(engagement)
    hits = scan(pub, terms)
    leaks = [h for h in hits if h[0] == "LEAK"]
    plats = [h for h in hits if h[0] == "platform"]

    print(f"packet     {slug}")
    print(f"engagement {engagement}")
    print(f"checked    {sum(len(f) for _, _, f in os.walk(pub))} file(s) in public/ "
          f"against {len(terms)} identifying term(s)\n")

    if leaks:
        print(f"⛔ {len(leaks)} LEAK(S) — public/ names the target. Do NOT hand this to anyone.")
        for _, f, n, term, line in leaks[:20]:
            print(f"     {f}:{n}  '{term}'  …{line}…")
    else:
        print("✅ no identifying term from this engagement appears in public/")

    if plats:
        seen = sorted({t for _, _, _, t, _ in plats})
        print(f"\n⚠️  platform names present (not blocking, your call): {', '.join(seen)}")
        print("     A platform name plus the bug class narrows the target. Fine if the explainer "
              "genuinely needs it;\n     otherwise say 'a static-site hosting platform'.")

    print(f"\n{'FAIL — fix public/ before sharing' if leaks else 'PASS — public/ is safe to hand off'}")
    return 1 if leaks else 0


def new(slug, engagement):
    d = os.path.join(PACKET_ROOT, slug)
    if os.path.exists(d):
        print(f"{d} already exists — refusing to overwrite an existing packet.")
        return 2
    os.makedirs(os.path.join(d, "public"))
    os.makedirs(os.path.join(d, "private"))
    with open(os.path.join(d, ".engagement"), "w") as fh:
        fh.write(engagement + "\n")
    for name, body in _TEMPLATES.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    print(f"scaffolded {d}")
    print("  public/EXPLAIN-listen.md   spoken-word explainer  (anonymised)")
    print("  public/EXPLAIN-read.md     written explainer      (anonymised)")
    print("  private/VERIFY.md          the real walkthrough   (local only)")
    print("  private/README.md          index + why-this-one")
    print(f"\nFill them in, then:  python3 packet.py check {slug}")
    return 0


_TEMPLATES = {
    "public/EXPLAIN-listen.md": """PROMPT — read this, then do what it says. Do not read this prompt out loud.

I am going to LISTEN to your answer, not read it. That changes everything about how you write it.

No formatting of any kind. No markdown, headings, bullet points, numbered lists, tables, or code
blocks. No asterisks, hashes, backticks, arrows, or bullet characters. No URLs. No file paths.
Nothing that only makes sense to the eye — if it would be read aloud as punctuation salad, leave
it out entirely.

Write in plain spoken prose, in full sentences and ordinary paragraphs, the way a knowledgeable
instructor actually talks. Explain each technical term in passing the first time it appears. If you
must refer to something normally written as code or an address, describe it in words. Spell numbers,
addresses, and symbols out as words, and expand an acronym the first time before using it as words.

Deliver it as ONE single narrator speaking straight through, roughly eight to ten minutes spoken.
No dialogue, no second speaker, no interviewer, no question-and-answer, no character names — just one
calm, clear voice explaining the topic from start to finish. Do NOT frame it as part of a numbered
series and do NOT announce a lesson number: no "lesson one", no "the fifth lesson", no "in this
series". It is a single self-contained explainer that stands on its own.

No sound effects, no music, no stage directions.

Here is the material.

---

<!-- ANONYMISED. No organisation, product, hostname, or handle. Explain the BUG CLASS, not this
     instance. `packet.py check` will refuse if anything identifying appears here. -->

TODO: the explanation, in plain prose.

Cover: how the thing normally works · what goes wrong · a physical-world analogy · why it matters
· what is proven versus what is only suspected · how it is fixed · how this pattern shows up
elsewhere.
""",

    "public/EXPLAIN-read.md": """# <bug class> — written explainer

**Generic. No organisation, product, or hostname from any real engagement appears here.**
Safe to share, paste anywhere, or hand to an outside tool.

## The one-sentence version

TODO

## How it normally works

TODO

## How it breaks

TODO

## The analogy

TODO

## What can be observed from outside

TODO

## Why it matters

TODO

## The line that must not be crossed in the write-up

> What was proven, versus what was only inferred. State it plainly — a reviewer who spots an
> unproven claim stops trusting the whole report.

TODO

## Severity, honestly

TODO

## The fix

TODO

## The wider pattern

TODO
""",

    "private/VERIFY.md": """# Verify by hand — <finding>

> ⚠️ **LOCAL ONLY. Do not hand this file to an outside AI or paste it anywhere public.**
> It names a real program and real hosts. The `public/` files are the shareable versions.

**Engagement:** TODO · **Platform:** TODO · **Findings covered:** TODO

Every command below is read-only. Replace the handle if yours differs.

## Before you start — check on the program page

1. TODO — any exclusion that would make this finding not-applicable?
2. Their AI-use policy — is disclosure required, and in what form?

## Step 1 — TODO

```bash
TODO
```

**Expect:** TODO

## Step 2 — TODO

## Step 3 — the counter-example

Show the same platform / mechanism working correctly elsewhere. This converts "something is
broken" into "this specific thing is broken," and it is the cheapest credibility in the report.

## Step 4 — evidence to keep

Text output exactly as it appeared — do not retype or tidy. Screenshot only where the finding is
genuinely visual. Attach to the platform, never an external host.

## Step 5 — what to report back

- Anything that came back different from the expectations above
- Answers to the program-page questions

## Honesty check before submitting

The report will say you verified this yourself — after these steps, that is true.
It will NOT claim anything you did not actually demonstrate. State the limit plainly.
""",

    "private/README.md": """# <NN> — <finding title>

**Engagement:** TODO · **Platform:** TODO · **Findings covered:** TODO
**Created:** TODO

## What's in here

| File | What it is | Safe to hand to an outside AI? |
|---|---|---|
| `public/EXPLAIN-listen.md` | Spoken-word explainer, anonymised | ✅ Yes |
| `public/EXPLAIN-read.md` | Written explainer, anonymised | ✅ Yes |
| `private/VERIFY.md` | The real walkthrough | ⛔ No — local only |
| `private/README.md` | This file | ⛔ No |

Checked mechanically: `python3 packet.py check <slug>`

## Suggested order

1. Listen to `public/EXPLAIN-listen.md`
2. Skim `public/EXPLAIN-read.md`
3. Run `private/VERIFY.md`
4. Report back for the submission draft

## The thirty-second version

TODO

## Why this one first

TODO
""",
}


def promote(slug, engagement):
    """File the durable halves; leave the working copy alone.

    The packet directory lives under ~/Desktop/temp and the operator deletes it when done — which
    is correct for a scratch space and wrong for two of the four files in it:

      * The explainers describe a BUG CLASS, not an instance. The same dangling-DNS explainer
        serves every future dangling-DNS finding on any program. Rewriting it each time is waste,
        and they are anonymised so they can live anywhere.
      * VERIFY.md is the record of HOW a finding was checked. That belongs with the finding, in
        the engagement, next to the evidence — not in a directory scheduled for deletion.

    Nothing is moved. `promote` copies, so the operator's working copy keeps working.
    """
    d = os.path.join(PACKET_ROOT, slug)
    pub = os.path.join(d, "public")
    if not os.path.isdir(pub):
        print(f"no packet at {d}")
        return 2
    if not engagement:
        meta = os.path.join(d, ".engagement")
        engagement = open(meta).read().strip() if os.path.isfile(meta) else None
    if not engagement:
        print("no engagement recorded — pass --engagement")
        return 2

    # Refuse to file a leaking explainer into a permanent, propagated location.
    leaks = [h for h in scan(pub, forbidden_terms(engagement)) if h[0] == "LEAK"]
    if leaks:
        print(f"⛔ refusing to promote: public/ still names the target ({len(leaks)} leak(s)).")
        for _, f, n, term, _ in leaks[:5]:
            print(f"     {f}:{n}  '{term}'")
        print("\nThe explainer library is anonymised by construction and gets propagated to a "
              "PUBLIC repo.\nFix public/ and re-run.")
        return 1

    import shutil
    lib = os.path.join(WORKSPACE, "global", "bug-class-explainers", _class_slug(slug))
    os.makedirs(lib, exist_ok=True)
    copied = []
    for fn in sorted(os.listdir(pub)):
        if fn.endswith(".md"):
            shutil.copy2(os.path.join(pub, fn), os.path.join(lib, fn))
            copied.append(os.path.join(lib, fn))

    vdir = os.path.join(ENG_ROOT, engagement, "06_Proof_of_Concept_and_Impact", "verification")
    src = os.path.join(d, "private", "VERIFY.md")
    if os.path.isfile(src):
        os.makedirs(vdir, exist_ok=True)
        dst = os.path.join(vdir, f"{slug}-VERIFY.md")
        shutil.copy2(src, dst)
        copied.append(dst)

    print("promoted (copied — your working directory is untouched):")
    for c in copied:
        print(f"  {c}")
    print("\nThe explainers are now reusable for any future finding of this class.")
    return 0


def _class_slug(slug):
    """`01-dangling-dns-delegation` -> `dangling-dns-delegation`. The library is keyed by class,
    not by the order this operator happened to work things."""
    return re.sub(r"^\d+[-_]", "", slug)


def cmd_list():
    if not os.path.isdir(PACKET_ROOT):
        print(f"no packets at {PACKET_ROOT}")
        return 0
    for slug in sorted(os.listdir(PACKET_ROOT)):
        d = os.path.join(PACKET_ROOT, slug)
        if not os.path.isdir(d):
            continue
        meta = os.path.join(d, ".engagement")
        eng = open(meta).read().strip() if os.path.isfile(meta) else "(unknown)"
        pub = os.path.join(d, "public")
        status = "no public/"
        if os.path.isdir(pub) and eng != "(unknown)":
            status = "LEAKS" if [h for h in scan(pub, forbidden_terms(eng)) if h[0] == "LEAK"] else "clean"
        print(f"  {slug:<38} {eng:<42} public/: {status}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Operator verification packets.")
    ap.add_argument("action", choices=["new", "check", "promote", "list"])
    ap.add_argument("slug", nargs="?")
    ap.add_argument("--engagement")
    a = ap.parse_args(argv)
    if a.action == "list":
        return cmd_list()
    if not a.slug:
        ap.error("slug required")
    if a.action == "new":
        if not a.engagement:
            ap.error("--engagement required for `new`")
        return new(a.slug, a.engagement)
    if a.action == "promote":
        return promote(a.slug, a.engagement)
    return check(a.slug, a.engagement)


if __name__ == "__main__":
    raise SystemExit(main())
