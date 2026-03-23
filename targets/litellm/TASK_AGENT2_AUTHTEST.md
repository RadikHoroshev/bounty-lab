# Task: LiteLLM Security Testing — Agent 2 (Auth & Privilege)

## Pre-conditions (verify before starting)

- [ ] Agent 1 must be complete: `ls /tmp/litellm_readiness.json /tmp/litellm_routes.json` → both files must exist
- [ ] litellm is running: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/liveliness` → must return 200
- [ ] Master key works: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/models` → must return 200

---

## Phase 1 — Confirm the /health/readiness finding (repeat 3 times)

Run each command exactly 3 times and record all 3 status codes. Finding is valid only if all 3 runs return 200.

**Run 1:**
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/readiness` → status: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health` → status: ___ (must be 401)

**Run 2 (wait 2 seconds):**
- [ ] `sleep 2 && curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/readiness` → status: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health` → status: ___ (must be 401)

**Run 3 (new shell session — no cached state):**
- [ ] Open new terminal and run: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/readiness` → status: ___

**Result:** Finding confirmed if all 3 readiness calls = 200 AND all /health calls = 401

---

## Phase 2 — Test /debug/asyncio-tasks (repeat 3 times)

- [ ] Run 1: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/debug/asyncio-tasks` → status: ___
- [ ] Run 2: `sleep 2 && curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/debug/asyncio-tasks` → status: ___
- [ ] Run 3: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/debug/asyncio-tasks` → status: ___
- [ ] Compare with protected debug endpoint: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/debug/memory/summary` → must be 401

---

## Phase 3 — Privilege escalation test (regular user vs admin)

- [ ] Generate a regular user API key:
  ```
  curl -s -X POST http://localhost:4000/key/generate \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"models": ["ollama/llama3.2"], "duration": "1h"}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('key','ERROR'))"
  ```
  Record user key: `sk-___________________`

- [ ] Test user key can access its own info: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_KEY" http://localhost:4000/key/info` → expected 200

- [ ] Test user key CANNOT list all keys: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_KEY" http://localhost:4000/key/list` → expected 401 or 403

- [ ] Test user key CANNOT see all users: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_KEY" http://localhost:4000/user/list` → expected 401 or 403

- [ ] Test user key CANNOT see spend logs: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_KEY" http://localhost:4000/spend/logs` → expected 401 or 403

- [ ] Test user key CANNOT access global spend: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_KEY" http://localhost:4000/global/spend` → expected 401 or 403

**If any of the last 4 checks returns 200 → that is a privilege escalation finding!**
**Record exact endpoint and response body.**

---

## Phase 4 — Source code verification of finding

- [ ] Find the readiness endpoint definition:
  ```
  grep -rn "def health_readiness\|readiness" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null | grep "async def" | head -5
  ```
  Record file path and line number: ___

- [ ] Check if `user_api_key_auth` is in the same function:
  ```
  grep -rn "health_readiness" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null | head -5
  ```

- [ ] Confirm `/health` HAS auth (for comparison):
  ```
  grep -rn "async def health\b\|def health(" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null | head -5
  ```

---

## Phase 5 — Check if already reported/fixed in newer version

- [ ] Check latest litellm version: `pip3 show litellm | grep Version`
- [ ] Check GitHub for existing issues:
  Search `https://github.com/BerriAI/litellm/issues` for "health/readiness" or "information disclosure"
  Record if similar issue exists: YES / NO

---

## Final verification checklist

All must be TRUE to submit as a real finding:

- [ ] `/health/readiness` returns 200 in all 3 test runs without any auth header
- [ ] `/health` (same base path) returns 401 without auth — proves inconsistency
- [ ] Response contains `litellm_version` field with a real version string
- [ ] Response contains `success_callbacks` array with security hook names
- [ ] Source code confirms missing `Depends(user_api_key_auth)` on readiness route
- [ ] Not already fixed in current installed version (1.82.6)
- [ ] No GitHub issue already open for this exact endpoint

**Write final verdict here:** CONFIRMED / FALSE POSITIVE / ALREADY KNOWN
**Reason:** ___
