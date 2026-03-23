# Bounty Lab

Центральный репозиторий для AI/ML bug bounty research.

## Структура

```
bounty-lab/
├── docs/
│   ├── sessions/          — журналы сессий (что делали, что нашли)
│   ├── research/          — исследования инструментов и методологии
│   └── architecture/      — архитектура системы, Jules specs
├── targets/
│   ├── litellm/           — ✅ 4 репорта отправлены
│   ├── ollama/            — ✅ 1 репорт отправлен
│   └── open-webui/        — ✅ 1 репорт отправлен
├── tools/
│   ├── mcp-stack.md       — конфигурация MCP инструментов
│   └── scripts/           — вспомогательные скрипты
├── reports/
│   ├── submitted/         — финальные отправленные репорты
│   └── drafts/            — черновики
├── templates/
│   └── nuclei/            — кастомные Nuclei шаблоны
├── knowledge/             — база знаний, паттерны уязвимостей
├── WORKFLOW.md            — рабочий процесс команды
└── README.md
```

## Быстрый старт

```bash
# Посмотреть все находки
ls targets/*/finding_*.md

# Текущий статус
cat docs/architecture/SECURITY_EMPIRE_STATUS_2026-03-23.md

# Запустить мониторинг (после Jules PRs)
python monitors/huntr_monitor.py
```

## MCP стек

| Инструмент | Назначение |
|-----------|-----------|
| `semgrep` | Статический анализ — ищет уязвимости в коде |
| `nuclei` | Динамическое сканирование по шаблонам |
| `playwright` | E2E тесты в браузере |
| `chrome-devtools` | Дебаггинг сети и JS |
| `codex` | Написание тестов и скриптов |
| `brave-search` | Поиск CVE и методологии |

Подробнее: [tools/mcp-stack.md](tools/mcp-stack.md)

## Прогресс

**Отправлено репортов:** 6
**В ожидании:** ~2-4 недели на трейж
**Потенциальная выплата:** $2,000–$15,000+
