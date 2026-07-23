# Sandbox Upgrade Log — <engagement>

Structured record of every **live patch** applied to a sandboxed copy of a production tool during
this engagement. The production original is never touched — only the copy under
`engagements/<name>/sandbox/<tool>/`. A validated patch here can later be merged back into the
production tool in **Tier 1 maintenance mode** (separate, operator-approved, git-versioned).

> Copy this file to `engagements/<name>/sandbox/UPGRADE_LOG.md`. It is git-ignored.

---

## [YYYY-MM-DD HH:MM] — <tool>@sandbox — <short title>

- **Tool (sandbox path):** engagements/<name>/sandbox/<tool>/...
- **Symptom / error context:** what failed or was missing against the target architecture
- **Change made:** exact edit (file + what changed)
- **Why:** why this patch was needed to maintain testing momentum
- **Result:** worked / partial / rolled back
- **Promote to production?** no  (only via Tier 1 maintenance, operator-approved)

---
<!-- append new entries above this line -->
