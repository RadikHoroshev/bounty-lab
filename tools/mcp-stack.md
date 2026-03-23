# MCP Stack — Конфигурация инструментов
**Обновлено:** 2026-03-23

## Подключённые MCP серверы (Claude Code)

| Сервер | Команда | Назначение | Статус |
|--------|---------|-----------|--------|
| `context7` | HTTP MCP | Документация библиотек | ✅ |
| `brave-search` | `npx @modelcontextprotocol/server-brave-search` | Поиск в интернете | ✅ |
| `obsidian` | `npx mcp-obsidian` | База знаний | ✅ |
| `notebooklm` | `uvx notebooklm-mcp` | Google NotebookLM | ✅ |
| `playwright` | `npx @playwright/mcp@latest` | E2E browser testing | ✅ |
| `codex` | `codex mcp-server` | Написание кода/тестов | ✅ |
| `codex-global` | `codex mcp-server -c ...` | Codex с доступом к диску | ✅ |
| `semgrep` | `npx -y semgrep-mcp` | Статический анализ кода | ✅ |
| `chrome-devtools` | `npx -y @chrome-devtools/mcp-server` | Chrome DevTools debug | ✅ |
| `nuclei` | `npx -y nuclei-mcp` | Nuclei vulnerability scan | ✅ |

## Добавить вручную (требует GUI)

### Burp Suite MCP (PortSwigger)
1. Открыть Burp Suite → Extensions → BApp Store
2. Найти "MCP Server" → Install
3. SSE endpoint: `http://127.0.0.1:9876/sse`

```bash
# После установки в Burp:
claude mcp add --scope user burpsuite -- npx -y @portswigger/mcp-proxy --sse-url http://127.0.0.1:9876
```

## AI CLI Arsenal

```bash
claude --version   # 2.1.81 — архитектор, дирижер
codex --version    # 0.98.0 — разработчик
gemini --version   # 0.33.1 — анализ больших файлов (1M context)
qwen --version     # 0.10.5 — сканер/специалист
ollama --version   # 0.18.2 — локальные модели
```

## Установка заново (если нужно)

```bash
# Playwright
npm install -g @playwright/mcp
npx playwright install

# Semgrep
pip install semgrep   # v1.156.0 уже установлен

# Nuclei
# уже установлен через brew/go

# Chrome DevTools MCP (Node.js 22+ required — ✅ v22.21.0)
npx -y @chrome-devtools/mcp-server
```
