# Bug Bounty Reports — Submission Status (2026-03-24)

## ТЕКУЩЕЕ СОСТОЯНИЕ (обновлено: 2026-03-24 22:00)

**Активная задача:** внедрение 3-ступенчатой системы проверки
**Шаг:** все известные находки отправлены, система верификации задокументирована
**Следующее действие:** искать новые находки; применять 3-stage process к каждой новой

---

## ✅ SUBMITTED

### LiteLLM SSTI/RCE via /prompts/test
- **huntr URL:** https://huntr.com/bounties/2328178c-6ad1-46c5-b9d5-8d22cd9e1880
- **Status:** ✅ Submitted 2026-03-23
- **CVSS:** 9.0 Critical — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
- **CWE:** CWE-1336
- **Type:** Server-Side Template Injection → RCE
- **Report file:** `litellm-ssti-rce-full-report.md`
- **Verify script:** `verify_litellm_ssti.py`
- **Note:** TODO — add occurrences: gitlab (L93), arize (L77), bitbucket (L77)

### LiteLLM SSRF via api_base Parameter
- **huntr URL:** https://huntr.com/bounties/bbd1ca0d-cd95-4840-9394-48db0074cb9f
- **Status:** ✅ Submitted 2026-03-24
- **CVSS:** 7.7 High — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N
- **CWE:** CWE-918
- **Type:** Server-Side Request Forgery
- **Report file:** `litellm-api-base-ssrf.md`
- **Verify script:** `verify_litellm_ssrf.py`
- **Occurrences:** gpt_transformation.py#L665-691, primitives.py#L308-322, router.py#L2353-2371

### Ollama SSRF via /api/experimental/web_fetch
- **huntr URL:** https://huntr.com/bounties/465a0ac8-29ed-47fe-9051-727ce2955d3d
- **Status:** ✅ Submitted 2026-03-24
- **CVSS:** 8.1 High
- **Type:** Server-Side Request Forgery (CWE-918)
- **Report file:** `ollama-web-fetch-ssrf.md`
- **Verify script:** `verify_ollama_ssrf.py`

### NLTK Arbitrary File Read via URL Field
- **huntr URL:** https://huntr.com/bounties/22559e83-0021-4f36-a0a6-73b2f0585cb4
- **Status:** ✅ Submitted 2026-03-23
- **CVSS:** 5.9 Medium
- **Type:** File Read + pathsec.ENFORCE=False bypass (CWE-918)

### Ollama DoS (GGUF integer overflow)
- **huntr URL:** https://huntr.com/bounties/9bcaca28-44f4-422d-aa49-4b090a8f9b22
- **Status:** ✅ Submitted 2026-03-22
- **Bounty:** $750

### Open WebUI Admin Info Disclosure
- **huntr URL:** https://huntr.com/bounties/c543e137-449e-48ac-a899-ab89f34ec307
- **Status:** ✅ Submitted 2026-03-21

### Open WebUI Embedding Unauthenticated
- **huntr URL:** https://huntr.com/bounties/590fc810-d6fa-45d5-aa06-878bad764af6
- **Status:** ✅ Submitted 2026-03-21

### LiteLLM CORS misconfiguration
- **huntr URL:** https://huntr.com/bounties/776834d0-6fb8-4191-b7af-cc0e56826c00
- **Status:** ✅ Submitted 2026-03-22

### LiteLLM JWT/HttpOnly
- **huntr URL:** https://huntr.com/bounties/4bed3c92-6a20-4031-882d-1697f8b41b4e
- **Status:** ✅ Submitted 2026-03-22

### LiteLLM IDOR /key/info
- **huntr URL:** https://huntr.com/bounties/535895a2-e11a-463d-bb53-9fee47e0197a
- **Status:** ✅ Submitted 2026-03-22

### LiteLLM Info Disclosure
- **huntr URL:** https://huntr.com/bounties/5d375293-2430-44d2-b93f-5bf391350483
- **Status:** ✅ Submitted 2026-03-22

---

## 📋 Summary Table

| Project | Finding | Severity | Status |
|---------|---------|----------|--------|
| LiteLLM | SSTI/RCE via /prompts/test | **9.0 Critical** | ✅ Submitted |
| LiteLLM | SSRF via api_base | 7.7 High | ✅ Submitted |
| Ollama | SSRF via web_fetch | 8.1 High | ✅ Submitted |
| Ollama | DoS GGUF overflow | High | ✅ Submitted |
| NLTK | Arbitrary File Read | 5.9 Medium | ✅ Submitted |
| LiteLLM | CORS misc | Low | ✅ Submitted |
| LiteLLM | JWT/HttpOnly | Low | ✅ Submitted |
| LiteLLM | IDOR /key/info | Low | ✅ Submitted |
| LiteLLM | Info Disclosure | Low | ✅ Submitted |
| Open WebUI | Admin Info Disclosure | Low | ✅ Submitted |
| Open WebUI | Embedding Unauth | Low | ✅ Submitted |

---

## 🔧 3-Stage Verification — Status per Script

| Script | STAGE 1 | STAGE 2 | STAGE 3 |
|--------|---------|---------|---------|
| `verify_litellm_ssti.py` | ✅ PASS (2026-03-24) | ✅ PASS (exit A=1, B=0, RCE confirmed) | ✅ APPROVED |
| `verify_litellm_ssrf.py` | ✅ PASS (6 bugs found+fixed) | pending re-run | — |
| `verify_ollama_ssrf.py` | ✅ PASS (0 bugs) | — | — |

---

## Следующие действия

1. Дождаться ревью всех 11 репортов
2. Добавить occurrences к SSTI репорту: gitlab (L93), arize (L77), bitbucket (L77)
3. Искать новые находки — следующие цели: MLflow (37 semgrep findings), Langchain, Open WebUI v2
4. Каждый новый репорт проходит полный 3-stage process перед отправкой

## File Locations
- Reports: `/Users/rodion/projects/bounty-lab/findings/`
- Verify scripts: same directory
- Standard: `/Users/rodion/projects/bounty-lab/BOUNTY_STANDARD.md`
- Roles: `/Users/rodion/projects/bounty-lab/AGENT_ROLES.md`
