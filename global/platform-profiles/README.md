# Platform Profiles

Standing, **platform-level** defaults the agent loads at the start of every engagement so the
operator never re-states the platform's baseline rules. One file per bug-bounty platform.

- **Platform profile** (here) = things true of the *whole platform* — its code of conduct, its
  standard "always ineligible" findings, its identifier conventions, its disclosure norms.
- **Program policy** (per engagement, brought in with the target) = things true of the *specific
  program* — exact in-scope assets, bounty table, program-specific exclusions, and critically
  **whether automated testing is permitted**.

The program policy always **overrides** the platform default when stricter.

## How the agent uses these
At engagement start (see the Initialization protocol in `global/CLAUDE.md`), the agent:
1. Identifies the platform (HackerOne, Bugcrowd, Intigriti, self-hosted, …) and loads that profile.
2. Runs the **PRE-FLIGHT GATE** in the profile against the specific program's policy — most
   importantly: *is automated scanning/tooling permitted?* If **not**, the agent must switch to
   manual-only mode or STOP and flag the operator. (This is the lesson from Agoda Public, which
   bans automated scanning outright — running `ffuf`/`nuclei`/`sqlmap` there risks an account ban.)
3. Expands any shorthand the program relies on — e.g. HackerOne's "Core Ineligible Findings are out
   of scope" expands to the full list in `hackerone.md`, so the operator doesn't paste it each time.

## Files
- `hackerone.md` — HackerOne platform profile (Core Ineligible Findings, identifier conventions,
  disclosure, and the pre-flight gate).
- `intigriti.md` — Intigriti platform profile (`@intigriti.me` identity, per-program attribution
  headers, the automation/no-scanner gate, tiers, contextual CVSS, strict disclosure, safe harbour).
- _(add `bugcrowd.md`, etc. as programs on those platforms come up.)_

## Note
These are **reference/default** knowledge. The authoritative per-run authorization is still the
loaded engagement's `scope.md` + `approved_TTPs.yaml` + the enforcement hook. A profile never
widens scope — it only encodes platform defaults and safety gates.
