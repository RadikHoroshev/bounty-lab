# Bug Bounty Reports — Submission Status (2026-03-24)

## ТЕКУЩЕЕ СОСТОЯНИЕ (обновлено: 2026-03-24)

**Активная задача:** отправка LiteLLM отчётов на huntr.com
**Шаг:** верификация завершена — готово к отправке формы

**Следующее действие для нового агента:**
1. Открыть huntr.com/bounties/new
2. Отправить LiteLLM SSTI/RCE (CVSS 9.0) — файл `litellm-ssti-rce-full-report.md`
3. Затем LiteLLM SSRF (CVSS 8.2) — файл `litellm-api-base-ssrf.md`
4. Оба скрипта (`verify_litellm_ssti.py`, `verify_litellm_ssrf.py`) прикладываются как вложения
5. После отправки — сохранить huntr URL в этот файл и в memory/project_security_research.md

---

## ✅ SUBMITTED

### Ollama SSRF via /api/experimental/web_fetch
- **huntr URL:** https://huntr.com/bounties/465a0ac8-29ed-47fe-9051-727ce2955d3d
- **Status:** ✅ Submitted 2026-03-24
- **CVSS:** 8.1 High
- **Type:** Server-Side Request Forgery (CWE-918)
- **Bounty:** $750
- **Report file:** `ollama-web-fetch-ssrf.md` (232 lines)
- **Verify script:** `verify_ollama_ssrf.py` (365 lines)

### NLTK Arbitrary File Read via URL Field
- **huntr URL:** https://huntr.com/bounties/22559e83-0021-4f36-a0a6-73b2f0585cb4
- **Status:** ✅ Submitted 2026-03-23
- **CVSS:** 5.9 Medium
- **Type:** File Read + pathsec.ENFORCE=False bypass (CWE-918)
- **Bounty:** $125–$175

---

## 🟡 READY FOR SUBMISSION (VERIFIED)

### LiteLLM SSRF via api_base Parameter
- **Status:** ⏳ Ready — all content verified, no errors found
- **CVSS:** 8.2 High (higher than Ollama)
- **Type:** Server-Side Request Forgery (CWE-918)
- **Report file:** `litellm-api-base-ssrf.md` (235 lines)
- **Verify script:** `verify_litellm_ssrf.py` (302 lines)
- **Checklist:** `LITELLM_SUBMISSION_CHECKLIST.md`

**Vulnerable locations identified:**
- `litellm/main.py` (lines 2389-2395, 5385-5387)
- `litellm/llms/openai/chat/gpt_transformation.py` (lines 665-691)
- `litellm/proxy/proxy_server.py` (lines 5385-5387)
- `litellm/router.py` (lines 515-516)
- `litellm/proxy/guardrails/custom_code/primitives.py` (lines 308-322)

**Additional findings:**
- API key leakage in exception messages (HIGH)
- Environment variable exposure (MEDIUM)

**Test URLs (9 patterns):** AWS IMDS, GCP metadata, Azure metadata, localhost variants, RFC1918 ranges, legitimate HTTPS

---

## 🟠 READY BUT NOT IN MEMORY (CRITICAL SEVERITY)

### LiteLLM SSTI/RCE via /prompts/test Endpoint
- **Status:** ⏳ Complete report, verify script ready
- **CVSS:** 9.0 Critical ⚠️ (highest severity)
- **Type:** Server-Side Template Injection → Remote Code Execution
- **CWE:** CWE-1336 (Improper Neutralization of Special Elements in Template Engine)
- **Affected:** ≤ 1.82.6
- **Report file:** `litellm-ssti-rce-full-report.md` (363 lines)
- **Verify script:** `verify_litellm_ssti.py` (172 lines)
- **Note:** Distinct from prior CVE-2024-2952 (different code path)
- **Created:** 2026-03-23
- **Not yet submitted to huntr.com**

**Key Details:**
- Endpoint: `POST /prompts/test`
- Code path: `litellm/integrations/dotprompt/prompt_manager.py:62`
- Jinja2 environment is NOT sandboxed
- Requires only valid API key (no admin role needed)
- Leads to full RCE in context of proxy process
- Attacker can exfil LLM provider keys, database creds, master key

**Verification approach:** Tests vulnerable Jinja2 environment directly (no running LiteLLM instance needed)

---

## Summary Table

| Project | Finding | Severity | Status | Files |
|---------|---------|----------|--------|-------|
| Ollama | SSRF via web_fetch | 8.1 | ✅ Submitted | .md + .py |
| NLTK | File Read (URL) | 5.9 | ✅ Submitted | .md |
| LiteLLM | SSRF via api_base | 8.2 | 🟡 Ready | .md + .py |
| LiteLLM | SSTI/RCE | **9.0** | 🟠 Ready | .md + .py |

---

## Recommended Next Steps

1. **Submit LiteLLM SSRF** (8.2 High) — higher severity than Ollama
   - Follow same process as Ollama submission
   - Use LITELLM_SUBMISSION_CHECKLIST.md

2. **Submit LiteLLM SSTI/RCE** (9.0 Critical) — HIGHEST PRIORITY
   - This is the most critical finding across all targets
   - Potential bounty: $4000+ (typical for RCE)
   - Distinct from prior CVE-2024-2952
   - Complete report with verification script included

3. **Continue MLflow research** (37 semgrep findings, 750 bounty available)

---

## File Locations
- Reports: `/Users/rodion/projects/bounty-lab/findings/`
- Verify scripts: same directory
- System docs: `/Users/rodion/projects/bounty-lab/BOUNTY_SYSTEM.md`
