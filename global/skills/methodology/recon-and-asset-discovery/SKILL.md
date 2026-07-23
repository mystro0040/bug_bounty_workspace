---
name: recon-and-asset-discovery
description: Scope-driven passive and active reconnaissance to map a target's attack surface (subdomains, DNS, ASN/IP, content, JS endpoints, tech stack); use at the start of any engagement to build an in-scope asset inventory before hunting.
---

# Recon & Asset Discovery

Goal: build a complete, accurate map of the **in-scope** attack surface. Bad recon = wasted hunting or, worse, testing something out of scope. Recon quality directly predicts payout.

## Non-negotiable rules
- Enumerate only assets that resolve to **in-scope** domains/IP ranges from the loaded engagement. Wildcard scope (`*.target.example.com`) still excludes explicitly listed out-of-scope hosts — check the exclusion list.
- Passive recon first. It is quiet, safe, and never destructive. Escalate to active only inside scope.
- Active content discovery is bounded: **respect rate limits**, no aggressive threading against fragile hosts, never treat brute-forcing as a stress test.
- Third-party assets (SaaS, CDNs, shared infra) are usually out of scope even if discovered. Confirm ownership before touching.

## Phase 0 — Load & pin scope
- Pull scope from the engagement definition. Record in-scope apex domains, wildcards, explicit hosts, IP/CIDR ranges, and the exclusion list.
- Build allow/deny lists as files so every downstream tool filters against them:
  - `scope_domains.txt`, `scope_cidrs.txt`, `out_of_scope.txt`

## Phase 1 — Passive subdomain enumeration
```bash
# Aggregate passive sources
subfinder -d target.example.com -all -silent -o subs_subfinder.txt
amass enum -passive -d target.example.com -o subs_amass.txt
# Certificate transparency
curl -s 'https://crt.sh/?q=%25.target.example.com&output=json' \
  | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u > subs_crtsh.txt
# Merge + dedupe
cat subs_*.txt | sort -u > subs_all.txt
```
Other passive sources worth adding: `github-subdomains`, `chaos` (ProjectDiscovery dataset), Wayback/`gau`, `assetfinder`.

## Phase 2 — Resolve & validate (filter to scope)
```bash
# Resolve to live hosts
dnsx -l subs_all.txt -a -resp -silent -o resolved.txt
# Keep only in-scope, then find live web services
httpx -l subs_all.txt -silent -status-code -title -tech-detect \
  -web-server -o live_hosts.txt
```
Cross-check every resolved IP against `scope_cidrs.txt`. Drop anything pointing at third-party infrastructure.

## Phase 3 — DNS, ASN & IP intelligence
```bash
# ASN / owned ranges (confirm ownership before treating as in-scope)
amass intel -asn <ASN> -o asn_ranges.txt
whois -h whois.radb.net -- '-i origin AS<N>' | grep -Eo 'route:.*'
# DNS records + zone hygiene
dig +short target.example.com any
dnsx -l subs_all.txt -cname -resp-only   # hunt dangling CNAMEs (subdomain takeover)
```
Flag dangling CNAMEs pointing to unclaimed SaaS (S3, Azure, Heroku, GitHub Pages) — potential subdomain takeover (high impact, see web-vulnerability-hunting).

## Phase 4 — Active content discovery (rate-limited)
```bash
# Directory/file discovery — tune -t (threads) and -rate down for fragile hosts
ffuf -u https://target.example.com/FUZZ -w raft-medium-directories.txt \
  -mc 200,204,301,302,307,401,403 -rate 50 -o ffuf.json
feroxbuster -u https://target.example.com -w raft-medium-words.txt \
  --scan-limit 4 --rate-limit 50 -o ferox.txt
gobuster dir -u https://target.example.com -w common.txt -t 20 -o gobuster.txt
# Virtual-host discovery
ffuf -u https://target.example.com -H "Host: FUZZ.target.example.com" \
  -w subs_wordlist.txt -fs <baseline_size>
```
Prioritize discovering: admin panels, API roots (`/api`, `/graphql`), staging/dev hosts, backup files, `.git/`, config/env files, upload endpoints.

## Phase 5 — JS analysis for endpoints & secrets
```bash
# Collect JS, extract endpoints and secrets
gau target.example.com | grep -Ei '\.js(\?|$)' | sort -u > js_urls.txt
cat js_urls.txt | while read u; do
  curl -s "$u" -o "js/$(echo "$u" | md5sum | cut -c1-12).js"; done
# Endpoints
grep -rEoh '(/[a-zA-Z0-9_./-]+)' js/ | sort -u > js_endpoints.txt
# Secrets (API keys, tokens) — treat as findings, do NOT use the key beyond proof
trufflehog filesystem js/ --only-verified
```
Tools: `LinkFinder`, `SecretFinder`, `jsluice`, `nuclei -t exposures/`. Any live secret is a finding — capture minimal proof, never abuse it.

## Phase 6 — Tech fingerprinting
```bash
httpx -l live_hosts.txt -tech-detect -json -o tech.json
whatweb -i live_hosts.txt --log-brief whatweb.txt
nuclei -l live_hosts.txt -t technologies/ -t exposures/ -rate-limit 50
```
Map framework/version → known CVEs, default creds, and framework-specific bug classes (e.g. SSTI on template engines, deserialization on Java/.NET).

## Deliverable: asset inventory
Produce a single `inventory.md` / CSV:
`host | ip | in_scope(y/n) | tech | interesting_paths | notes`

## De-prioritize (noise, not payable on their own)
- Missing security headers, verbose `Server:`/`X-Powered-By` banners.
- Non-sensitive `robots.txt`/directory listings with nothing useful.
- Findings on out-of-scope or third-party assets — do not report, do not test.

## Feed forward
Hand the inventory + `js_endpoints.txt` + auth endpoints to **web-vulnerability-hunting** and **api-and-auth-testing**.

## When rate-limited / WAF-blocked: go offline, don't stall
If the target starts blocking (429 / WAF challenge), you don't have to stop making progress — pivot to
OFFLINE analysis of already-captured data: re-mine saved JS bundles for endpoints, secrets, and
`sourceMappingURL` (.js.map) references; parse saved response bodies for logic; build the endpoint
inventory for the next authenticated pass. Pairs with the WAF circuit-breaker (CLAUDE.md §2G) — back off
the wall, keep working from what you already have.
