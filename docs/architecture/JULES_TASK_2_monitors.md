# Jules Task 2 — Intelligence Monitors

## Цель
Два скрипта которые запускаются по cron и уведомляют о новых возможностях для bug bounty.

## Файлы
- `/Users/rodion/projects/security-empire/monitors/huntr_monitor.py`
- `/Users/rodion/projects/security-empire/monitors/github_watcher.py`
- `/Users/rodion/projects/security-empire/monitors/notify.py`

---

## notify.py — Telegram уведомления

```python
# Отправляет сообщение в Telegram через bot API
# TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID из env переменных

async def send_telegram(message: str, urgent: bool = False):
    ...
```

Формат сообщения:
```
🔴 URGENT: Новая программа на huntr!
📦 Название: AnythingLLM
🔗 https://huntr.com/...
💰 Max bounty: $3000
⏰ Добавлено: 5 минут назад
```

---

## huntr_monitor.py

### Что делает
1. Парсит https://huntr.com/bounties (публичный список программ)
2. Сравнивает с `/monitors/state/huntr_programs.json` (предыдущее состояние)
3. Если новая программа → notify(urgent=True)
4. Проверяет статусы репортов из `/monitors/state/my_reports.json`
5. Если статус изменился → notify()

### Список моих репортов (захардкодить):
```python
MY_REPORTS = [
    {"id": "5d375293", "title": "Info disclosure", "repo": "litellm"},
    {"id": "535895a2", "title": "IDOR key/info", "repo": "litellm"},
    {"id": "4bed3c92", "title": "JWT session mgmt", "repo": "litellm"},
    {"id": "776834d0", "title": "CORS misconfig", "repo": "litellm"},
]
```

### Запуск
```bash
python3 monitors/huntr_monitor.py
python3 monitors/huntr_monitor.py --status  # только проверка репортов
```

---

## github_watcher.py

### Что делает
1. Для каждого репо из WATCH_LIST проверяет latest release через GitHub API
2. Сравнивает с `/monitors/state/github_releases.json`
3. Если новый релиз → notify() + записать в `/monitors/inbox/new_release_REPO.md`

### WATCH_LIST
```python
WATCH_LIST = [
    "BerriAI/litellm",
    "ollama/ollama",
    "open-webui/open-webui",
    "langchain-ai/langchain",
    "FlowiseAI/Flowise",
    "Mintplex-Labs/anything-llm",
    "lobehub/lobe-chat",
    "cheshire-cat-ai/core",
    "mudler/LocalAI",
]
```

### Уведомление при новом релизе
```
📦 Новый релиз: litellm v1.83.0
🔗 https://github.com/BerriAI/litellm/releases/tag/v1.83.0
📝 Changelog highlights:
  - New endpoint: /v2/admin/...
  - Changed auth: ...
⚡ Действие: запустить recon pipeline
```

### Генерирует файл /monitors/inbox/new_release_litellm_v1.83.0.md
```markdown
# New Release: litellm v1.83.0

## Diff от предыдущей версии
[список изменённых файлов из GitHub API /compare]

## Новые endpoints (grep из diff)
- ...

## Изменения в auth/security
- ...

## Рекомендуемые проверки
- [ ] Проверить новые endpoints на auth bypass
- [ ] Проверить изменения в JWT логике
- [ ] Запустить nuclei scan
```

---

## Требования
- Python 3.14, asyncio, httpx
- State хранится в JSON файлах (не БД)
- Никогда не крашиться — все ошибки логировать в stderr
- GitHub API без токена (60 req/hour) — достаточно для мониторинга
- Комментарии на русском
