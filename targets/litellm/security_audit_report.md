# LiteLLM Security Audit Report — Auth & Privilege
**Version:** 1.82.6
**Date:** March 2026
**Status:** Submitted to huntr — [#5d375293](https://huntr.com/bounties/5d375293-2430-44d2-b93f-5bf391350483)
**CVSS:** 5.3 Medium (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor

---

## Executive Summary

A security audit of litellm proxy v1.82.6 identified two unauthenticated information disclosure vulnerabilities and one unauthenticated API surface enumeration endpoint. Three findings were confirmed via independent testing (Agent 1 + Agent 2 + neutral verification script — all produced identical results).

---

## Finding 1 — GET /health/readiness (Authentication Bypass)

**Description:** The `/health/readiness` endpoint returns detailed server configuration to any unauthenticated client despite having a `Depends(user_api_key_auth)` decorator.

**Root Cause:**
- Endpoint defined in `litellm/proxy/health_endpoints/_health_endpoints.py` with `@router.get("/health/readiness", dependencies=[Depends(user_api_key_auth)])`
- BUT `/health/readiness` is explicitly listed in `LiteLLMRoutes.public_routes` in `litellm/proxy/_types.py` (line 588)
- In `litellm/proxy/auth/user_api_key_auth.py` (lines 632–637), `_user_api_key_auth_builder` detects the route in `public_routes` and returns `UserAPIKeyAuth(user_role=LitellmUserRoles.INTERNAL_USER_VIEW_ONLY)` **before any token validation** — causing the dependency to succeed unconditionally

**Proof of Concept:**
```bash
curl http://TARGET:4000/health/readiness
```

**Response (no auth required):**
```json
{
  "status": "healthy",
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

**Inconsistency:** `GET /health` (same server) returns HTTP 401 without auth. `GET /health/liveliness` intentionally returns only `"I'm alive!"` (minimal, acceptable). Only `/health/readiness` leaks sensitive config.

**Sensitive data exposed:**
| Field | Risk |
|-------|------|
| `litellm_version` | Version-targeted CVE lookup |
| `success_callbacks` | Reveals active security middlewares by name — enables targeted bypass attempts |
| `log_level: WARNING` | Attacker knows INFO events are not logged |
| `db: "Not connected"` | DB state for timing analysis |
| `is_detailed_debug: false` | Debug mode status |

---

## Finding 2 — GET /debug/asyncio-tasks (Missing Auth Decorator)

**Description:** The `/debug/asyncio-tasks` endpoint exposes running asyncio task coroutine names and state without any authentication.

**Root Cause:** Endpoint in `litellm/proxy/common_utils/debug_utils.py` (lines 53–85) completely omits `dependencies=[Depends(user_api_key_auth)]`. FastAPI enforces no auth checks. Compare: `/debug/memory/summary` (nearby route, same file) correctly returns HTTP 401.

**Proof of Concept:**
```bash
curl http://TARGET:4000/debug/asyncio-tasks
```

**Known Issues:** No CVEs found for this endpoint. Not already reported.

---

## Finding 3 — GET /routes (Full API Map Without Auth)

**Description:** Returns all 738 registered API routes including 149 admin paths (`/key/`, `/user/`, `/spend/`, `/global/`) without authentication.

**Root Cause:** `/routes` is in `LiteLLMRoutes.public_routes` (same as Finding 1).

**Impact:** Provides a complete attack surface map to unauthenticated clients.

---

## Source Code References

- `litellm/proxy/_types.py` lines 582–598 — `public_routes` set definition
- `litellm/proxy/auth/user_api_key_auth.py` lines 632–637 — early return for public_routes
- `litellm/proxy/common_utils/debug_utils.py` lines 53–85 — missing auth decorator
- Permalink: https://github.com/BerriAI/litellm/blob/main/litellm/proxy/_types.py#L582-L598

---

## Verification

Tested independently by:
1. `verify_findings.py` — neutral verification script, 19 checks, 3 findings confirmed
2. Antigravity Agent 1 (recon) — endpoint mapping + source analysis
3. Antigravity Agent 2 (auth testing) — repeated 3× each, source code tracing, GitHub duplicate check

All three produced identical results.

---

## Recommended Fixes

1. **`/health/readiness`** — Remove from `public_routes`, or strip sensitive fields:
   ```python
   @router.get("/health/readiness")
   async def health_readiness():
       return {"status": "healthy"}
   ```

2. **`/debug/asyncio-tasks`** — Add auth decorator:
   ```python
   @router.get("/debug/asyncio-tasks", dependencies=[Depends(user_api_key_auth)])
   ```

3. **`/routes`** — Remove from `public_routes` or restrict to admin role
