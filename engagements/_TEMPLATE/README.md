# Engagement structure (standard)

Every engagement is organized by the 7 bug-bounty methodology phases below (mirrors the
master `bug-bounty-execution-framework`). Copy this `_TEMPLATE/` for a new engagement, or the
`/generate-scope` flow scaffolds it. `scope.md` + `NOTES.md` sit at the engagement root; the
target copy (if any) lives in `target/`.

1. **01_Pre_Engagement** — scope, rules, test accounts, approval
2. **02_Reconnaissance** — passive recon & asset discovery
3. **03_Scanning_and_Enumeration** — content discovery (endpoints, params, dirs), roles, APIs
4. **04_Vulnerability_Analysis** — candidates (common + logical/business-logic)
5. **05_Exploitation_PoC** — minimal non-destructive proof
6. **06_Proof_of_Concept_and_Impact** — evidence + impact
7. **07_Reporting** — final per-finding reports
