---
name: passive-recon-and-osint
description: Passive and light-active reconnaissance for bug bounty — subdomain/DNS/ASN discovery, GitHub/source-code secret hunting, document metadata, and passive web recon (Wayback, tech fingerprinting). Use at the start of a program to map the in-scope attack surface without touching targets aggressively.
---

# Passive Recon & OSINT (bug-bounty-safe subset)

Distilled from the user's Pentest Execution Framework — this is the **bug-bounty-safe subset** of Phase 02 (Reconnaissance). Only passive and low-noise active recon is kept. Password spraying, breach-credential stuffing, MFA-bypass, phishing/physical OSINT, and any credential attacks from the source are intentionally dropped.

> Authorized, in-scope engagements only — verify the target is within the loaded engagement's scope/ROE before use. Runnable examples use placeholder targets, not real third parties.

## Non-negotiable rules
- Enumerate only assets that resolve to in-scope domains/IP ranges. Confirm ownership before treating discovered infra as in-scope.
- Stay passive first: interacting like an organic user (browsing, header grabs) is fine; do not tamper with parameters or send injection probes in this phase.
- Third-party SaaS/CDN assets discovered here are usually out of scope — do not test them.

## Subdomain & asset enumeration
```bash
subfinder -d target.example.com -all -recursive > subdomains.txt
assetfinder --subs-only target.example.com >> subdomains.txt
amass enum -passive -d target.example.com -o amass_subs.txt      # deeper, slower
cat subdomains.txt amass_subs.txt | sort -u > unique_subs.txt
# Live web hosts only
cat unique_subs.txt | httprobe -s -p https:443 > alive.txt
gowitness file -f alive.txt --threads 4    # visual triage; gowitness server -> :7171
```
- Hunt naming conventions: `dev.`, `staging.`, `uat.`, `test.`, `legacy.` — often unpatched, no WAF/MFA.
- **Dangling CNAMEs → subdomain takeover.** Flag CNAMEs pointing at unclaimed S3/GitHub Pages/Heroku.

## ASN / IP ownership
```bash
whois -h whois.radb.net -- '-i origin AS<N>' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq
```
Or search the org name at `bgp.he.net` to confirm routed ranges belong to the target.

## Cloud storage enumeration
```bash
python3 cloud_enum.py -k targetcompany     # AWS/Azure/GCP exposed buckets/containers
```
Companies name buckets predictably: `target-backups`, `target-assets`, `target-dev`.

## GitHub / source-code OSINT (passive)
```bash
# Secrets in a target's public repos — keep verification OFF to stay passive
trufflehog github --org=targetcompany --no-verification
gitleaks detect -v --source=./target_repo         # local clone
# Native history grep across all commits/branches
git rev-list --all | xargs git grep -i -E "password|secret|api_key|token"
```
Secrets live forever in commit history even after deletion. Check Gists, PR/Issue comments (leaked stack traces, internal IPs), and personal dev accounts. Any live secret is a **finding** — capture minimal proof, never use the key.

## Document metadata
```bash
metagoofil -d target.example.com -t pdf,doc,docx,xlsx -l 50 -n 50 -o ./docs
exiftool -csv -r ./docs > all_metadata.csv       # authors, internal paths, software versions
strings target.pdf | grep -i "\\\\"              # internal UNC paths if no exiftool
```
Metadata leaks usernames, internal share paths, and outdated software versions (report as information disclosure where in scope).

## Passive web recon
```bash
echo "target.example.com" | waybackurls > wayback.txt
gau target.example.com > gau.txt                  # Wayback + OTX + CommonCrawl
curl -I -s https://target.example.com             # headers, server version (WAF-ignored)
```
- Filter historical URLs for juicy items: `.json`, `.js`, `.bak`, `?id=`, `/api/v1/`. Manually test surviving endpoints.
- Always check `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`.
- Fingerprint the stack passively with Wappalyzer/BuiltWith rather than active `whatweb`.

## Deliverable
`inventory.md`: `host | ip | in_scope | tech | interesting_paths | notes`. Feed alive hosts + endpoints forward to **web-content-discovery** and **web-vulnerability-analysis**.
