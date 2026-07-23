# Bug Bounty Workspace — root config loader

<!-- Claude Code auto-loads THIS file from the workspace root, then imports the full global
     configuration below. The authoritative agent config, hard rules, and scope-gating
     guardrails live in global/CLAUDE.md. -->

@global/CLAUDE.md

---

Operational reminder: on every session, follow the **Initialization protocol** and
**Phase 1 (Initialization check)** in the global config before doing anything else. If the
selected engagement has no populated `approved_TTPs.yaml`, you are locked down — tell the
operator to run `/generate-scope <engagement>` first.
