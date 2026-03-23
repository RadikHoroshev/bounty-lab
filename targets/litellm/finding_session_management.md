# Finding: Insecure Session Management in LiteLLM Proxy UI

**Target:** litellm proxy v1.82.6  
**Date:** 2026-03-22  
**Severity:** MEDIUM (CVSS 6.5)  
**CWE:** CWE-613 (Insufficient Session Expiration), CWE-1004 (Sensitive Cookie Without HttpOnly Flag)  
**Reporter:** CLAUDE (security research)

---

## Summary

The litellm proxy admin UI issues JWT session tokens with three critical weaknesses:
1. JWT has no `exp` claim — tokens never expire
2. Session cookie has no `HttpOnly` flag — accessible via `document.cookie`
3. JWT payload embeds the user's actual API key in plaintext
4. No logout/invalidation endpoint (`/logout` → 404)

Combined: a stolen session token provides permanent admin access with no revocation path.

---

## Evidence

### 1. Login and Cookie Capture

```bash
curl -sv -X POST http://TARGET:4000/v2/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "MASTER_KEY"}'
```

**Response header:**
```
set-cookie: token=eyJhbGci...; Path=/; SameSite=lax
```

Note: **No `HttpOnly`**, **No `Secure`** flags.

### 2. JWT Payload (base64-decoded)

```json
{
  "user_id": "default_user_id",
  "key": "sk-E8oNXXjNXRY-7jaxaaKmrQ",
  "user_email": null,
  "user_role": "proxy_admin",
  "login_method": "username_password",
  "premium_user": false,
  "auth_header_name": "Authorization",
  "disabled_non_admin_personal_key_creation": false,
  "server_root_path": ""
}
```

**No `exp` claim** → token never expires.  
**`key` field** → contains the user's actual LiteLLM API key in the session token.

### 3. JWT Contains Valid API Key

```bash
# Extract key from JWT and use it directly
curl http://TARGET:4000/user/list \
  -H "Authorization: Bearer sk-E8oNXXjNXRY-7jaxaaKmrQ"
# → 200 OK with admin access
```

### 4. No Logout Mechanism

```bash
curl http://TARGET:4000/logout
# → 404 Not Found
```

No mechanism exists to invalidate issued tokens.

---

## Attack Scenario

1. Victim logs into litellm UI at `http://company-litellm.internal/ui`
2. JWT token set in `token` cookie without `HttpOnly`
3. Any reflected/stored XSS on the same domain can steal `document.cookie`
4. Attacker extracts `key` from stolen JWT — gets permanent admin API key
5. No expiry, no revocation → access persists forever

Or without XSS: if session token is leaked via logs, browser history, or network capture (no `Secure` flag), attacker gains permanent admin access.

---

## Source Code Reference

`litellm/proxy/proxy_server.py:11120`:
```python
json_response.set_cookie(key="token", value=jwt_token)
# No httponly=True, no secure=True, no max_age
```

`litellm/proxy/proxy_server.py:11103-11107`:
```python
jwt_token = jwt.encode(
    cast(dict, returned_ui_token_object),  # contains "key" field
    cast(str, master_key),
    algorithm="HS256",
    # No exp claim
)
```

---

## CVSS 3.1

`AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` = **7.5 HIGH**

- AC:H because requires XSS or token leak first
- S:C because token gives access to entire LiteLLM admin
- C:H + I:H because all API keys + admin operations

Standalone (no XSS needed, just token leak):  
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 CRITICAL** (if token exposed)

---

## Recommended Fix

```python
json_response.set_cookie(
    key="token",
    value=jwt_token,
    httponly=True,     # Prevent JS access
    secure=True,       # HTTPS only
    samesite="strict", # CSRF protection
    max_age=3600       # 1-hour session
)

# JWT with expiry:
jwt_token = jwt.encode(
    {**returned_ui_token_object, "exp": time.time() + 3600},
    master_key,
    algorithm="HS256"
)
```

---

**Files:**  
- `litellm/proxy/proxy_server.py:11071, 11120, 11288` — `set_cookie` calls without HttpOnly  
- `litellm/proxy/proxy_server.py:11103` — JWT creation without `exp`

