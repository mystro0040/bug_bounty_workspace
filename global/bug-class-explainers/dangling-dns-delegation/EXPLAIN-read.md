# Dangling DNS delegation (subdomain takeover) — written explainer

**Generic. No organisation, product, or hostname from any real engagement appears here.**
Safe to share, paste anywhere, or hand to an outside tool.

---

## The one-sentence version

A company points part of its domain at a hosting platform, later deletes the site on that
platform, and never removes the pointer — so the name still leads somewhere the company no longer
occupies.

---

## How the plumbing works

DNS turns a name into a destination. Two record types matter here:

| Record | Means |
|---|---|
| **A** | "This name lives at this IP address." |
| **CNAME** | "Don't ask me — ask this other name instead." |

A CNAME is a forwarding instruction. It's how nearly every company attaches a subdomain to a
hosting platform they don't own:

```
sub.company.example.   CNAME   customer-site-abc123.platform.example.
```

Now a browser asking for `sub.company.example` is told to go to the platform, and the platform
looks up which of *its* customer sites is registered under that name and serves it.

This is normal, correct, and everywhere.

---

## How it breaks

Rebrand, migration, product retirement. Someone tears down the old site **on the platform** —
that happens, because it's costing money and somebody sees the invoice.

**The DNS record costs nothing.** No invoice, no alert, no failing test. It survives.

Result:

```
sub.company.example.   CNAME   customer-site-abc123.platform.example.
                                        ↓
                               platform has no such site
                                        ↓
                        "Site Not Found" / "DEPLOYMENT_NOT_FOUND"
```

The name still resolves. The platform still answers. There is just nothing behind it.

---

## The analogy

You tell the post office to forward your mail to **Suite 400, Acme Building**.
Later you move out and cancel the lease — but never cancel the forwarding.

Your mail still goes to the Acme Building. Suite 400 is still there. It's empty.

**And it's available to rent.**

Whoever rents it next receives your mail. They broke into nothing. Your own forwarding instruction
delivered it.

- **Acme Building** = the hosting platform
- **Suite 400** = the site name inside that platform
- **The forwarding instruction** = your CNAME record

---

## What you can observe from outside

Entirely passive. Two steps:

1. **Read the CNAME.** Does it point at a third-party hosting platform?
2. **Request the host.** Does the platform disown it?

Platform disown-messages vary but are unmistakable:

| Platform family | Says |
|---|---|
| Static-site host A | `Site Not Found` |
| Static-site host B | `DEPLOYMENT_NOT_FOUND` |
| Code-hosting pages | `There isn't a ... site here` |
| Object storage | `NoSuchBucket` |

You are not attacking anything. You are reading a public DNS record and requesting a public URL.

---

## Why it matters

If an attacker registers that name on the platform, they control content at an address that
**genuinely belongs to the company**.

1. **Real domain.** Not a typosquat. The actual name, actually owned by the target.
2. **Real TLS certificate.** The platform issues one automatically for whatever it hosts. The
   padlock is genuine.
3. **Cookie reach.** Anything scoped to `*.company.example` may be readable from attacker content,
   depending on flags. A forgotten record on a trivial subdomain can reach the main service.

The checks a careful user is taught — *is the domain right, is there a padlock* — **all pass.**

**The name of the abandoned host sets the ceiling on impact.** A marketing page is bad. Anything
named for authentication is much worse, because the people who arrive there are the ones about to
type a password.

---

## The line that must not be crossed in the write-up

> **Finding the suite is empty is not the same as proving you can rent it.**

Most platforms now require **domain-ownership verification** — usually a TXT record only the real
owner can add — before attaching a custom domain. So:

| Claim | Supported by outside observation? |
|---|---|
| The CNAME points at the platform | **Yes** |
| The platform serves nothing there | **Yes** |
| Someone else could claim it | **No** |

Proving the third means performing an action **on the hosting platform's systems** — a different
company, not party to the engagement, that never consented. So it isn't done.

Report what was observed. State plainly what wasn't established. Let the owner check their own
account records.

**This is not caution for its own sake.** A reviewer who spots an unproven takeover claim stops
trusting the whole report. A reviewer who sees the researcher draw that line unprompted reads
everything else with confidence.

---

## Severity, honestly

| Situation | Realistic rating |
|---|---|
| Dangling state observed, claim not attempted | **Low / Informational** |
| Claim demonstrated with a benign proof page | **High / Critical** |
| Dangling on an auth-related host, claim demonstrated | **Critical** |

Some programs explicitly exclude *"subdomain takeover without taking over the subdomain."*
**Check the program's exclusions before writing** — if that clause is present, the undemonstrated
version will be closed as not-applicable.

---

## The fix

Delete the record, or point it at something real. Roughly one minute of work.

The difficulty was never the fixing — it's the **noticing**. Nothing breaks, nothing alerts,
nobody is billed for a DNS record aimed at empty space. Which is why these survive for years.

---

## Reporting it well

**One report per root cause, not one per hostname.** Several abandoned records usually trace back
to a single event — a rebrand, a migration, a retirement. Saying *"your cleanup was incomplete,
here are four survivors"* is far more useful to the owner than four separate tickets, and it
implies there may be more they haven't found.

**Include a working counter-example.** Show a host on the *same platform* that resolves correctly.
That converts "a host is 404ing" into "these specific records are abandoned, and here's the proof
it isn't a platform quirk." It's the cheapest credibility in the whole report.

---

## The wider pattern

The shape recurs far beyond DNS: **the thing was decommissioned, the pointer to it survived.**

- Server retired, firewall rule permitting it remains
- Employee leaves, their token stays valid
- Service shut down, its credential is never revoked
- Feature removed, the flag enabling it stays in config

In every case the asset is gone and the reference is not, and the danger lives entirely in the
surviving reference. Learn to look for the gap between *what was removed* and *what still points
at it*.
