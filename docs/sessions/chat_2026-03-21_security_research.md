# Чат 21 марта 2026 — Security Research Session

## Что сделали

### Finding #3 — Admin Information Disclosure (Open WebUI 0.8.8)

**Уязвимость:** `GET /api/v1/auths/admin/details` возвращает имя и email администратора любому аутентифицированному пользователю.

**Подтверждение (4 прогона):**
```
🔴 GET /api/v1/auths/admin/details → 200
   {'name': 'Родион', 'email': 'rodion@local.test'}
   (запрос от role=user)
```

**CVSS:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = **4.3 Medium**
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Root cause:** `Depends(get_verified_user)` вместо `Depends(get_admin_user)` в `backend/open_webui/routers/auths.py`

---

## Итог тестирования (advanced_tester.py)

| Тест | Результат |
|------|-----------|
| JWT Structure Leakage | Только id/exp/jti — роли нет ✅ |
| Role escalation | 405 Blocked ✅ |
| Admin details (victim) | **200 🔴 БАГИ** |
| Admin config/users list | 401 Blocked ✅ |
| Function injection (victim) | 401 Blocked ✅ |
| Model name injection | 405 Blocked ✅ |
| IDOR modify admin | 405 Blocked ✅ |
| Knowledge base enum | Пустой список, не баг ✅ |
| Config export | SPA HTML, не баг ✅ |

---

## Сабмит на huntr

- **URL отчёта:** https://huntr.com/bounties/c543e137-449e-48ac-a899-ab89f34ec307
- **Статус:** Awaiting review
- **Подан:** 21 марта 2026

---

## GitHub портфолио обновлён

**Repo:** https://github.com/RadikHoroshev/security-research
**Коммит:** `bb99b50` — update finding #3 status: submitted to huntr

| # | Таргет | Баг | CVSS | Статус |
|---|--------|-----|------|--------|
| 1 | Ollama GGUF Parser | DoS via integer overflow in `readGGUFString` | 7.5 High | ✅ Confirmed |
| 2 | Open WebUI — Embedding | Unauthenticated `/retrieval/ef/{text}` | 5.3 Medium | ✅ Submitted |
| 3 | Open WebUI — Admin Disclosure | Any user reads admin name+email | 4.3 Medium | ✅ Submitted |

---

## Скрипты

| Скрипт | Путь |
|--------|------|
| Основной тестер | `~/projects/security-research/open-webui/advanced_tester.py` |
| Настройка окружения | `~/projects/security-research/open-webui/setup_test_env.sh` |
| Warp bridge | `~/projects/hub/claude_warp_bridge.sh` |
| Документация бага | `~/projects/security-research/open-webui/finding_admin_details_disclosure.md` |

**Запуск тестера:**
```bash
cd ~/projects/hub && ./claude_warp_bridge.sh run 'python3 ~/projects/security-research/open-webui/advanced_tester.py'
```

**Credentials:**
- Admin: `rodion@local.test` / `Rodion2024`
- Test user: `user@local.test` / `User2024`

---

## На завтра

Построить структуру для тестирования и отладки — модульный фреймворк (Python/bash) для будущих проектов по настройке и debugging.
