# Finding #4 — Sensitive Info Disclosure via /health/readiness in litellm

**Target:** [BerriAI/litellm](https://github.com/BerriAI/litellm)
**Version:** 1.82.6
**Date:** March 2026
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**CVSS:** AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = **5.3 Medium**
**Status:** Ready to submit

---

## Summary

The `GET /health/readiness` endpoint returns detailed server configuration to any unauthenticated client. This includes the server version, names of active security callback hooks, transport configuration, and debug settings — none of which should be visible without credentials.

---

## Inconsistency

| Endpoint | Auth Required | Response |
|----------|--------------|----------|
| `GET /health/liveliness` | ❌ No | `"I'm alive!"` (minimal, acceptable) |
| `GET /health` | ✅ Yes (401) | Full model health info |
| **`GET /health/readiness`** | **❌ No** | **Detailed server config (VULNERABLE)** |

---

## Proof of Concept

```bash
curl http://TARGET:4000/health/readiness
```

**Response (no authentication required):**

```json
{
  "status": "healthy",
  "db": "Not connected",
  "cache": null,
  "litellm_version": "1.82.6",
  "success_callbacks": [
    "SkillsInjectionHook",
    "_PROXY_VirtualKeyModelMaxBudgetLimiter",
    "_PROXY_MaxBudgetLimiter",
    "_PROXY_MaxParallelRequestsHandler_v3",
    "_PROXY_CacheControlCheck",
    "ResponsesIDSecurity",
    "_PROXY_MaxIterationsHandler",
    "_PROXY_MaxBudgetPerSessionHandler",
    "ServiceLogging"
  ],
  "use_aiohttp_transport": true,
  "log_level": "WARNING",
  "is_detailed_debug": false
}
```

---

## Sensitive Data Exposed

| Field | Risk |
|-------|------|
| `litellm_version` | Enables version-targeted attacks |
| `success_callbacks` list | Reveals active security controls (allows targeted bypass attempts) |
| `db: "Not connected"` | Reveals DB state (useful for timing attacks) |
| `log_level: "WARNING"` | Reveals logging config (attacker knows actions may not be logged) |
| `is_detailed_debug: false` | Reveals debug mode |
| `use_aiohttp_transport` | Reveals transport layer |

The `success_callbacks` list is particularly sensitive — it reveals which security middlewares are **active**, their exact internal class names, and their order of execution. An attacker can use this to identify which defenses are in place and craft requests that target gaps.

---

## Root Cause

The `/health/readiness` endpoint does not apply the `user_api_key_auth` dependency:

```python
# Vulnerable (no auth check):
@router.get("/health/readiness")
async def health_readiness():
    return {...detailed config...}

# Compare with /health (protected):
@router.get("/health")
async def health(user_api_key_dict=Depends(user_api_key_auth)):
    ...
```

**Suggested fix:**

```python
@router.get("/health/readiness")
async def health_readiness(user_api_key_dict=Depends(user_api_key_auth)):
    # Or return minimal response without sensitive fields:
    return {"status": "healthy"}
```

---

## Impact

Any unauthenticated attacker on the network can:
1. Identify the exact litellm version for targeted CVE lookup
2. Enumerate active security callbacks to understand the security architecture
3. Know the logging level (WARNING means many INFO events are not logged)
4. Determine DB connection state for timing attacks
