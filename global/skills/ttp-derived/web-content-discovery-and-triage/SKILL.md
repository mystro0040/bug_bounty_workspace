---
name: web-content-discovery-and-triage
description: Safe, scoped web enumeration for bug bounty — content/directory discovery, polite web fuzzing (FFUF/feroxbuster), vhost & parameter discovery, WAF fingerprinting, visual triage, and secret hunting in fetched source/JS. Use after recon to expand a single web target's surface without hammering fragile hosts.
---

# Web Content Discovery & Triage (bug-bounty-safe subset)

Distilled from the user's Pentest Execution Framework — the **bug-bounty-safe subset** of Phase 03 (Web Enumeration & Fuzzing / Web Triage & Secrets). Aggressive network scanning, service brute-forcing, and internal LOLBin pivoting from the source are dropped.

> Authorized, in-scope engagements only — verify the target is within the loaded engagement's scope/ROE before use. Runnable examples use placeholder targets, not real third parties.

## Politeness rules (non-negotiable for bug bounty)
- Respect rate limits: tune threads (`-t`) and add `-rate`/`--rate-limit`. Never treat fuzzing as a stress test.
- Back off fragile/legacy hosts. If a host slows or errors, reduce concurrency immediately.
- Fetch-once, search-infinite: download source once, run offline greps — quieter and kinder to the target.

## Fingerprint before fuzzing
```bash
whatweb -a 3 https://target.example.com          # CMS, server, language
wafw00f https://target.example.com               # WAF present? dictates aggressiveness
```

## Directory & file discovery (rate-limited)
```bash
ffuf -w raft-medium-words.txt:FUZZ -u https://target.example.com/FUZZ -fc 404 -rate 50
# Backup/source extensions devs leave behind
ffuf -w raft-medium-words.txt:FUZZ -u https://target.example.com/FUZZ \
  -e .php,.bak,.old,.txt,.zip,.tar.gz,.sql -fc 404 -rate 50
feroxbuster -u https://target.example.com -w raft-large-directories.txt \
  --scan-limit 4 --rate-limit 50 -x php,html,bak,txt,zip
```
- **403 ≠ 404.** A 403 means the file *exists* but is forbidden — note it for later bypass attempts (`X-Forwarded-For: 127.0.0.1`).
- Prioritize: admin panels, `/.git`, `/.env`, `/backup`, API roots (`/api`, `/graphql`, `/swagger-ui.html`), upload endpoints.

## Virtual host & parameter discovery
```bash
ffuf -w subdomains-top1million-5000.txt:FUZZ -u https://target.example.com/ \
  -H "Host: FUZZ.target.example.com" -mc 200,301,302
arjun -u https://target.example.com/endpoint --get      # hidden params (?debug=true)
```
Manually try common params (`?id=1`, `?page=admin`, `?file=`, `?url=`) — but keep values benign in this phase.

## Visual triage
```bash
gowitness file -f alive_urls.txt --threads 10
gowitness report server        # open localhost:7171
```
Screenshot large URL lists instead of opening each in a browser — spot default panels, open directory listings, exposed debug files fast.

## Secret hunting in fetched source
```bash
# Local-download method: meg fetches quietly, gf greps offline
meg -v / urls.txt ./downloaded_html
gf secrets ./downloaded_html/          # also: gf aws-keys, gf php-errors
# In-memory alternative (no disk artifacts)
cat urls.txt | httpx -silent -match-regex "password|api_key|secret|hidden"
```

## JavaScript triage
```bash
for url in $(cat alive_urls.txt); do
  curl -s "$url" | grep -oE "https?://[a-zA-Z0-9./_-]+\.js" >> js_endpoints.txt; done
cat js_endpoints.txt | sort -u | xargs -I {} curl -s {} | grep -riE "(api|token|key|secret|graphql)"
```
Downloading/greping JS source is safe (no JS execution). Look for `.js.map` files that un-minify front-end source, and hidden/legacy API endpoints.

## Feed forward
Hand discovered endpoints, parameters, panels, and any secrets to **web-vulnerability-analysis** and **web-app-exploitation-poc**. Any live secret is a finding — prove minimally, never abuse.
