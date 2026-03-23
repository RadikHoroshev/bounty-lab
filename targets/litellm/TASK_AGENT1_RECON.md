# Task: LiteLLM Security Recon — Agent 1 (Endpoint Mapping)

## Pre-conditions (verify before starting)

- [ ] Confirm litellm is running: `curl -s http://localhost:4000/health/liveliness` → must return `"I'm alive!"`
- [ ] If not running, start it: `LITELLM_MASTER_KEY="sk-master-test-1234" UVICORN_LOOP=asyncio /opt/homebrew/bin/litellm --port 4000 --model ollama/llama3.2 > /tmp/litellm.log 2>&1 &`
- [ ] Wait 10 seconds after start, then re-check liveliness

---

## Phase 1 — Unauthenticated endpoint scan

Run each curl exactly as written. Record **actual HTTP status code** — do not guess.

- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health` → expected 401, record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/liveliness` → expected 200, record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/readiness` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/models` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/routes` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/openapi.json` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/sso/debug/login` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/debug/asyncio-tasks` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/spend/logs` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/user/list` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/key/list` → record actual: ___
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/global/spend` → record actual: ___

---

## Phase 2 — Capture full response of open endpoints

Only do this for endpoints that returned 200 in Phase 1.

- [ ] Save `/health/readiness` response: `curl -s http://localhost:4000/health/readiness > /tmp/litellm_readiness.json && cat /tmp/litellm_readiness.json`
- [ ] Confirm response contains `litellm_version` field: `grep -c "litellm_version" /tmp/litellm_readiness.json` → must return 1
- [ ] Confirm response contains `success_callbacks` field: `grep -c "success_callbacks" /tmp/litellm_readiness.json` → must return 1
- [ ] Save `/routes` response: `curl -s http://localhost:4000/routes > /tmp/litellm_routes.json`
- [ ] Count total routes: `python3 -c "import json; d=json.load(open('/tmp/litellm_routes.json')); print('Routes:', len(d.get('routes',[])))"` → record count: ___
- [ ] Save `/debug/asyncio-tasks` if it was 200: `curl -s http://localhost:4000/debug/asyncio-tasks > /tmp/litellm_debug_tasks.json && cat /tmp/litellm_debug_tasks.json`

---

## Phase 3 — Verify finding is NOT a false positive

- [ ] Check if there is any documentation that `/health/readiness` is intentionally public:
  `grep -r "health/readiness" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null | grep -i "auth\|public\|skip" | head -5`
- [ ] Check if `/health/readiness` has auth dependency in source:
  `grep -A 5 "health/readiness\|health_readiness" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/auth/auth_checks.py 2>/dev/null | head -20`
- [ ] Search for the route definition to confirm no auth:
  `grep -rn "health_readiness\|readiness" /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null | grep "def \|router\|Depends" | head -10`

---

## Phase 4 — Save results

- [ ] Create summary: `echo "AGENT1 RESULTS $(date)" > /tmp/agent1_summary.txt`
- [ ] Append open endpoints to summary file
- [ ] Confirm `/tmp/litellm_readiness.json` exists and is non-empty: `wc -c /tmp/litellm_readiness.json`
- [ ] Confirm `/tmp/litellm_routes.json` exists and is non-empty: `wc -c /tmp/litellm_routes.json`

---

## Verification criteria (must all be true to confirm finding)

- [ ] `/health/readiness` returns HTTP 200 without any Authorization header
- [ ] Response body contains `litellm_version` (exact version string)
- [ ] Response body contains `success_callbacks` array with at least 3 entries
- [ ] `/health` (without `/readiness`) returns HTTP 401 without auth — confirming inconsistency
- [ ] Source code confirms no `Depends(user_api_key_auth)` on the readiness endpoint

**If all 5 checks are TRUE → finding is confirmed, not a false positive.**
**If any check is FALSE → record which one failed and stop.**
