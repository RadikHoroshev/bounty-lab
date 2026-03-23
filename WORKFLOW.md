# Bug Bounty Workflow — Рабочая группа
**Версия:** 1.0 | **Дата:** 2026-03-23

---

## Команда агентов

| Агент | Роль | Инструмент | Задача |
|-------|------|-----------|--------|
| **Claude** (Sonnet 4.6) | Архитектор + дирижер | claude CLI | Стратегия, анализ, репорты |
| **Jules** (Google) | Разработчик | jules.google.com | Написание кода, PR |
| **Codex** | Разработчик (sync) | `codex` MCP | Тесты, скрипты, рефакторинг |
| **Gemini 2.5 Flash** | Аналитик | `gemini` CLI | Анализ больших файлов (1M ctx) |
| **QWEN** | Сканер | `qwen` CLI | Технические проверки |
| **ATG-01** | Специалист | Antigravity | Nuclei templates, deep scan |

---

## Этапы работы по цели

### 1. РАЗВЕДКА (30 мин)
```bash
# Recon pipeline (когда Jules сделает)
python recon/recon.py --target TARGET_URL

# Вручную — маппинг эндпоинтов
curl -s TARGET/openapi.json | python3 -m json.tool
curl -s TARGET/api/version
```

### 2. СТАТИЧЕСКИЙ АНАЛИЗ (15 мин)
```
→ Claude: "Используй Semgrep MCP — просканируй код TARGET на уязвимости"
→ Semgrep находит опасные паттерны автоматически
→ Записываем в targets/TARGET/findings/
```

### 3. ДИНАМИЧЕСКОЕ ТЕСТИРОВАНИЕ (1-2 часа)
```
→ Playwright MCP — E2E тесты в браузере
→ Chrome DevTools MCP — захват network traffic
→ Burp Suite MCP — манипуляции с HTTP запросами
→ Nuclei MCP — шаблоны для известных CVE
```

### 4. ОФОРМЛЕНИЕ РЕПОРТА
```
→ Claude пишет профессиональный отчёт
→ Сохраняем в reports/submitted/ или reports/drafts/
→ Отправляем на huntr.com
```

---

## Автоматизация (когда Jules завершит PRs)

### Мониторы (jules-task-2)
- `monitors/huntr_monitor.py` — проверяет новые программы на huntr каждые 30 мин
- `monitors/github_watcher.py` — следит за релизами целей каждый час
- `monitors/notify.py` — Telegram уведомления

### Cron schedule
```bash
# Запустить мониторинг
python monitors/huntr_monitor.py &
python monitors/github_watcher.py &
```

---

## Текущие цели

| Цель | Программа | Макс. выплата | Статус |
|------|-----------|--------------|--------|
| **litellm** | huntr.com | $4,000+ | 4 репорта отправлены ✅ |
| **ollama** | huntr.com | $4,000 | 1 репорт отправлен ✅ |
| **open-webui** | huntr.com | $2,500 | 1 репорт отправлен ✅ |
| **следующая цель** | huntr.com | TBD | 🎯 Выбрать |

---

## Как выбрать следующую цель

```bash
# Поиск новых AI/ML программ на huntr
python monitors/huntr_monitor.py --list-new

# Критерии выбора:
# 1. Python/JS проект (можно статически анализировать)
# 2. Активен (коммиты за последние 30 дней)
# 3. Есть веб-интерфейс или API (тестировать через Playwright)
# 4. Высокий max bounty
```

---

## Документация сессий

Каждую сессию сохранять в:
```
docs/sessions/session_YYYY-MM-DD.md
```

Формат:
```markdown
# Сессия YYYY-MM-DD
## Цели сессии
## Что нашли
## Что отправили
## Следующие шаги
```
