# Security Empire — Architecture
**Owner:** rodion / radikhoroshev
**Platform:** huntr.com (AI/ML bug bounty)
**Stack:** Python 3.14, Node 22, Go 1.25, macOS arm64

---

## 🏗️ Система из 4 слоёв

```
┌─────────────────────────────────────────────────────────┐
│                    CLAUDE (Архитектор)                  │
│              Координация · Репорты · Huntr              │
└────────────────┬──────────────────┬─────────────────────┘
                 │                  │
    ┌────────────▼──────┐  ┌────────▼────────────┐
    │   MCP Security    │  │  Intelligence Feed   │
    │     Server        │  │  (Cron monitors)     │
    │  mcp-server/      │  │  monitors/           │
    └────────────┬──────┘  └────────┬────────────┘
                 │                  │
    ┌────────────▼──────────────────▼────────────┐
    │              Recon Pipeline                 │
    │  recon/ — clone → scan → report → triage   │
    └────────────────────┬───────────────────────┘
                         │
    ┌────────────────────▼───────────────────────┐
    │              Tool Arsenal                   │
    │  nuclei · ffuf · semgrep · nmap · sqlmap   │
    │  httpx · PyJWT · custom scripts             │
    └────────────────────────────────────────────┘
```

---

## 📁 Структура файлов

```
security-empire/
├── ARCHITECTURE.md          ← этот файл
├── targets/                 ← цели (по одному файлу на таргет)
│   ├── litellm.yaml
│   ├── ollama.yaml
│   ├── open-webui.yaml
│   └── _template.yaml
├── recon/
│   ├── recon.py             ← главный pipeline (Jules пишет)
│   ├── static_scan.py       ← semgrep + bandit враппер
│   ├── dynamic_scan.py      ← httpx + nuclei враппер
│   └── jwt_analyzer.py      ← JWT аудит (уже есть логика)
├── mcp-server/
│   ├── server.py            ← MCP Security Server (Jules пишет)
│   └── tools/
│       ├── cors_tester.py
│       ├── jwt_checker.py
│       ├── endpoint_mapper.py
│       └── rate_limiter.py
├── monitors/
│   ├── huntr_monitor.py     ← новые программы/статусы (Jules)
│   ├── github_watcher.py    ← новые релизы целей (Jules)
│   └── notify.py            ← Telegram уведомления
├── nuclei-templates/        ← кастомные шаблоны для AI/ML
│   ├── litellm-cors.yaml
│   ├── jwt-no-expiry.yaml
│   └── llm-info-disclosure.yaml
├── reports/                 ← авто-репорты
│   └── _template.md
└── tools/
    ├── install.sh           ← установка всего
    └── check_env.sh         ← проверка среды
```

---

## 🤖 Агенты и роли

| Агент | Роль | Задачи |
|-------|------|--------|
| **CLAUDE** | Архитектор + Huntr | Координация, репорты, анализ |
| **Jules (Google)** | Senior Developer | MCP server, recon pipeline, monitors |
| **ATG brains** | Специалисты | Конкретные scan модули |
| **QWEN** | Scanner | Запуск nuclei/ffuf/semgrep |

---

## 🎯 Приоритетные цели

| Таргет | Программа huntr | Сложность | Потенциал |
|--------|----------------|-----------|-----------|
| litellm | ✅ Активна | Medium | $$$ |
| ollama | ✅ Активна | Low | $$ |
| open-webui | ✅ Активна | Medium | $$$ |
| langchain | ? проверить | High | $$$$ |
| flowise | ? проверить | Low | $$ |
| anything-llm | ? проверить | Low | $$ |
| lobe-chat | ? проверить | Medium | $$$ |

---

## ⚡ Workflow

```
Новый таргет добавлен на huntr
        ↓
huntr_monitor.py → уведомление в Telegram (5 мин)
        ↓
recon.py TARGET_URL → автосканирование (30 мин)
  ├── git clone + semgrep (статика)
  ├── httpx endpoint map
  ├── nuclei scan
  └── JWT + CORS проверки
        ↓
report.md → Claude анализирует → приоритизация
        ↓
Ручное подтверждение → huntr submission
```

---

## 🔄 Cron расписание

| Задача | Интервал | Файл |
|--------|---------|------|
| Новые huntr программы | 30 мин | monitors/huntr_monitor.py |
| GitHub релизы целей | 1 час | monitors/github_watcher.py |
| Статус репортов | 6 часов | monitors/huntr_monitor.py --status |
| Полный rescan целей | еженедельно | recon/recon.py --all |
