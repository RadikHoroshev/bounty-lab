# ТЗ: Исследование инструментов тестирования и отладки
**Тип:** Research Task | **Дата:** 2026-03-23 | **Исполнитель:** AI Agent (Web Research)

---

## Цель исследования

Найти лучшие инструменты 2025-2026 года для:
1. Автоматизации тестирования программных продуктов
2. Отладки и диагностики кода
3. Интеграции с AI-агентами через MCP протокол
4. Специализированного тестирования безопасности (bug bounty)

---

## Направления исследования

### Блок A: MCP серверы для тестирования

**Что искать:**
- `site:github.com mcp server testing 2025`
- `"mcp server" pytest OR jest OR mocha`
- `modelcontextprotocol testing debugging tools`
- Официальный реестр MCP: https://github.com/modelcontextprotocol/servers

**Вопросы для ответа:**
- Какие официальные MCP серверы для тестирования существуют?
- Есть ли MCP для pytest / jest / vitest?
- Есть ли MCP для статического анализа (mypy, ruff, eslint)?
- Есть ли MCP для coverage репортов?

---

### Блок B: Браузерное тестирование через AI

**Что искать:**
- `playwright mcp 2025 features`
- `@playwright/mcp tools list`
- `stagehand browserbase mcp`
- `browser-use AI testing`

**Вопросы для ответа:**
- Какие инструменты Playwright MCP предоставляет?
- Как использовать для E2E тестирования API серверов?
- Альтернативы: Stagehand, BrowserBase, browser-use?
- Можно ли запускать headless для CI?

---

### Блок C: AI-assisted bug detection

**Что искать:**
- `AI code review security 2025 tools`
- `semgrep AI rules 2025`
- `codeql mcp integration`
- `snyk AI scanning`
- `github copilot autofix 2026`

**Вопросы для ответа:**
- Semgrep Pro vs Community — есть ли AI-правила для Python?
- CodeQL как MCP сервер?
- Новые AI-инструменты для поиска уязвимостей?
- Nuclei AI templates?

---

### Блок D: API testing tools

**Что искать:**
- `REST API testing MCP server 2025`
- `httpx pytest async testing best practices`
- `tavern API testing`
- `schemathesis API fuzzing`
- `dredd API contract testing`

**Вопросы для ответа:**
- Лучшие инструменты для тестирования FastAPI/Flask?
- Есть ли MCP для автоматического API fuzzing?
- Как интегрировать schemathesis с MCP агентами?

---

### Блок E: Monitoring & Observability

**Что искать:**
- `opentelemetry mcp server`
- `grafana mcp integration`
- `log analysis AI tools 2025`
- `error tracking AI sentry alternative`

**Вопросы для ответа:**
- Как настроить наблюдаемость для Python агентов?
- Есть ли MCP для Grafana / Prometheus?
- AI-инструменты для анализа логов?

---

### Блок F: Специально для Bug Bounty

**Что искать:**
- `AI tools bug bounty 2025`
- `automated vulnerability discovery AI`
- `nuclei AI templates generator`
- `burpsuite AI extension 2025`
- `caido AI security testing`

**Вопросы для ответа:**
- Новые AI-инструменты для автоматического поиска уязвимостей?
- Nuclei AI — как генерировать templates автоматически?
- Есть ли MCP серверы для OWASP checks?
- Caido vs Burp Suite для автоматизации?

---

## Ожидаемый формат результата

### Таблица инструментов

| Инструмент | Тип | Категория | Установка MCP | Цена | Оценка (1-10) |
|-----------|-----|-----------|--------------|------|---------------|
| @playwright/mcp | MCP | E2E тест | уже есть | Free | 9 |
| ... | ... | ... | ... | ... | ... |

### ТОП-3 рекомендации

1. **Срочно установить** (высокая ценность, легко настроить)
2. **Изучить** (перспективно, требует времени)
3. **Мониторить** (следить за развитием)

### Новинки 2025-2026

Инструменты, которые появились недавно и могут дать конкурентное преимущество.

---

## Контекст проекта (для агента)

**Наш стек:**
- Python 3.11+, FastAPI, asyncio, pytest
- Claude Code с MCP протоколом
- Playwright уже установлен
- Уже есть: brave-search, context7, obsidian, notebooklm, codex MCP серверы
- Работаем на macOS (darwin 25.3.0)
- Занимаемся bug bounty на AI/ML продуктах (huntr.com)
- Цели: litellm, ollama, open-webui, langchain, huggingface

**Что НЕ нужно:**
- Enterprise инструменты дороже $100/мес
- Инструменты только для Java/C++
- Устаревшие решения (не обновлялись > 2 лет)

---

*Создано: 2026-03-23 | Для запуска: brave-search MCP или gemini CLI*
