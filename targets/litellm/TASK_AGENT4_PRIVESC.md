# Task: LiteLLM Security Testing — Agent 4 (Privilege Escalation & Rate Limit Bypass)

## Goal
Test vertical privilege escalation (regular user → admin) and horizontal access control (user A sees user B's data). Also test spend limit bypass via header manipulation.

## Pre-conditions

- [ ] litellm is running: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/liveliness` → must return 200
- [ ] Master key works: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/models` → must return 200
- [ ] Start litellm WITH database if testing privesc. If DB unavailable, skip to Phase 3.

  **Start with DB (if PostgreSQL is running):**
  ```bash
  DATABASE_URL="postgresql://user:pass@localhost:5432/litellm" \
  LITELLM_MASTER_KEY="sk-master-test-1234" \
  UVICORN_LOOP=asyncio /opt/homebrew/bin/litellm --port 4000 --model ollama/llama3.2 > /tmp/litellm.log 2>&1 &
  sleep 10
  ```

---

## Phase 1 — Create two separate user keys (requires DB)

- [ ] Generate User A key:
  ```bash
  USER_A=$(curl -s -X POST http://localhost:4000/key/generate \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"models": ["ollama/llama3.2"], "duration": "1h", "metadata": {"role": "user_a"}}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('key','ERROR'))")
  echo "User A: $USER_A"
  ```

- [ ] Generate User B key:
  ```bash
  USER_B=$(curl -s -X POST http://localhost:4000/key/generate \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"models": ["ollama/llama3.2"], "duration": "1h", "metadata": {"role": "user_b"}}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('key','ERROR'))")
  echo "User B: $USER_B"
  ```

---

## Phase 2 — Privilege escalation: regular user → admin actions

Replace `USER_A_KEY` with the key from Phase 1.

- [ ] Can user A see ALL keys? `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" http://localhost:4000/key/list` → expected 403
- [ ] Can user A see ALL users? `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" http://localhost:4000/user/list` → expected 403
- [ ] Can user A see global spend? `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" http://localhost:4000/global/spend` → expected 403
- [ ] Can user A create new users?
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" \
    -H "Content-Type: application/json" \
    -X POST http://localhost:4000/user/new \
    -d '{"user_email": "evil@test.com", "user_role": "proxy_admin"}'
  ```
  → expected 403. **If 200 → critical finding!**

- [ ] Can user A elevate own role?
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" \
    -H "Content-Type: application/json" \
    -X POST http://localhost:4000/user/update \
    -d '{"user_role": "proxy_admin"}'
  ```
  → expected 403. **If 200 → critical finding!**

- [ ] Can user A add their key to internal user group?
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" \
    -H "Content-Type: application/json" \
    -X POST http://localhost:4000/key/update \
    -d '{"key": "USER_A_KEY", "user_role": "proxy_admin"}'
  ```
  → expected 403. **If 200 → privilege escalation!**

---

## Phase 3 — Horizontal access: user A reads user B's data

- [ ] Does user A's `/key/info` return only their key or others too?
  ```bash
  curl -s -H "Authorization: Bearer USER_A_KEY" "http://localhost:4000/key/info?key=USER_A_KEY" | python3 -m json.tool | head -20
  ```

- [ ] Can user A query user B's key info directly?
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer USER_A_KEY" \
    "http://localhost:4000/key/info?key=USER_B_KEY"
  ```
  → expected 403. **If 200 → IDOR finding!**

- [ ] Does `/spend/logs` with user A key return only their logs or all logs?
  ```bash
  curl -s -H "Authorization: Bearer USER_A_KEY" "http://localhost:4000/spend/logs" | python3 -m json.tool | head -30
  ```
  → Should return 403. If it returns data, check if it contains other users' data.

---

## Phase 4 — Rate limiting bypass via header manipulation

- [ ] Generate a key with a very low budget limit:
  ```bash
  LIMITED_KEY=$(curl -s -X POST http://localhost:4000/key/generate \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"models": ["ollama/llama3.2"], "duration": "1h", "max_budget": 0.001}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('key','ERROR'))")
  echo "Limited key: $LIMITED_KEY"
  ```

- [ ] Make a request that should hit the budget limit:
  ```bash
  curl -s -X POST http://localhost:4000/chat/completions \
    -H "Authorization: Bearer $LIMITED_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model": "ollama/llama3.2", "messages": [{"role": "user", "content": "hi"}]}'
  ```

- [ ] Try to bypass spend tracking via `X-Forwarded-For`:
  ```bash
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:4000/chat/completions \
    -H "Authorization: Bearer $LIMITED_KEY" \
    -H "X-Forwarded-For: 10.0.0.1" \
    -H "Content-Type: application/json" \
    -d '{"model": "ollama/llama3.2", "messages": [{"role": "user", "content": "hi"}]}'
  ```

- [ ] Try `user` parameter injection in request body to spoof identity:
  ```bash
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:4000/chat/completions \
    -H "Authorization: Bearer $LIMITED_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model": "ollama/llama3.2", "messages": [{"role": "user", "content": "hi"}], "user": "admin"}'
  ```
  → Check if `user` field allows identity spoofing

---

## Phase 5 — JWT / key forgery check

- [ ] Check if litellm accepts unsigned/weakly-signed JWTs:
  ```bash
  # Try a JWT with alg:none
  FAKE_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJwcm94eV9hZG1pbiJ9."
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $FAKE_JWT" \
    http://localhost:4000/user/list
  ```
  → expected 401. **If 200 → critical JWT alg:none vulnerability!**

- [ ] Check if empty/null key is accepted:
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer " http://localhost:4000/user/list
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer null" http://localhost:4000/user/list
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer undefined" http://localhost:4000/user/list
  ```
  → all must return 401

---

## Summary

**Record all results. Finding is confirmed if ANY of:**
- [ ] Phase 2: any admin endpoint returns 200 with user key → privilege escalation
- [ ] Phase 3: user A can read user B's key/spend data → IDOR
- [ ] Phase 4: spend tracking can be bypassed → rate limit bypass
- [ ] Phase 5: JWT alg:none accepted → critical auth bypass

**Write final verdict:** CONFIRMED / NOT CONFIRMED
**Findings:** ___
