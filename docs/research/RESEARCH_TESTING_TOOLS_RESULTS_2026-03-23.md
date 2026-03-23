# Исследование: Инструменты тестирования и отладки через MCP
**Дата:** 2026-03-23 | **Источник:** Brave Search + веб-поиск

---

## ТОП НАХОДКИ — Устанавливаем срочно

### 🥇 #1 — Semgrep MCP (ОФИЦИАЛЬНЫЙ)
**GitHub:** https://github.com/semgrep/mcp
**Что делает:** Сканирование кода на уязвимости прямо из Claude. 2000+ правил по безопасности, корректности, зависимостям.
**Установка:**
```bash
claude mcp add --scope user semgrep -- npx -y semgrep-mcp
```
**Цена:** Free (Open Source)
**Оценка:** 10/10 для bug bounty — ищет уязвимости в коде автоматически

---

### 🥇 #2 — Burp Suite MCP (ОФИЦИАЛЬНЫЙ от PortSwigger)
**GitHub:** https://github.com/PortSwigger/mcp-server
**Что делает:** Интеграция Burp Suite с AI. HTTP proxy history, манипуляции с запросами, сканирование уязвимостей.
**Установка:** Через Burp Suite BApp Store → установить extension MCP Server → запускается SSE на localhost:9876
**Цена:** Burp Suite Community = Free / Pro = $449/год
**Оценка:** 10/10 для bug bounty — это профессиональный инструмент безопасности + AI

---

### 🥇 #3 — Chrome DevTools MCP (ОФИЦИАЛЬНЫЙ от Google)
**GitHub:** https://github.com/ChromeDevTools/chrome-devtools-mcp
**Что делает:** Claude контролирует живой Chrome браузер. Elements, Network, Console, Performance profiler — всё доступно агенту.
**Установка:**
```bash
claude mcp add --scope user chrome-devtools -- npx -y @chrome-devtools/mcp-server
```
**Требования:** Node.js 22+, Chrome stable
**Цена:** Free
**Оценка:** 9/10 — дебаггинг веб-приложений, анализ network requests

---

### 🥈 #4 — MCP Inspector (ОФИЦИАЛЬНЫЙ от Anthropic)
**GitHub:** https://github.com/modelcontextprotocol/inspector
**Что делает:** Visual UI для тестирования и отладки MCP серверов. Подключается к серверу, отправляет тестовые запросы, смотрит логи.
**Установка:**
```bash
npx @modelcontextprotocol/inspector
```
**Цена:** Free
**Оценка:** 9/10 для разработки ivrit-ai-pro mcp_bridge — тестировать инструменты визуально

---

### 🥈 #5 — Nuclei MCP
**GitHub:** https://github.com/addcontent/nuclei-mcp
**Что делает:** Claude запускает Nuclei сканирование прямо из диалога. Все 9000+ шаблонов + кастомные.
**Установка:**
```bash
claude mcp add --scope user nuclei -- npx -y nuclei-mcp
```
**Цена:** Free
**Оценка:** 9/10 для bug bounty — автоматическое сканирование целей

---

### 🥈 #6 — AWS Security Scanner MCP
**GitHub:** https://github.com/aws-samples/sample-mcp-security-scanner
**Что делает:** 3 инструмента в одном: Checkov (IaC), Semgrep (code), Bandit (Python). Полный security scan.
**Установка:** Клонировать и запустить Python сервер
**Цена:** Free
**Оценка:** 8/10 — особенно Bandit для Python кода

---

## ПОЛНАЯ ТАБЛИЦА

| Инструмент | Категория | Установка MCP | Цена | Оценка |
|-----------|-----------|--------------|------|--------|
| **Semgrep MCP** (официальный) | Статический анализ | `npx semgrep-mcp` | Free | 10/10 |
| **Burp Suite MCP** (PortSwigger) | Web security | BApp extension | Free/Pro | 10/10 |
| **Chrome DevTools MCP** (Google) | Дебаггинг браузера | `npx @chrome-devtools/mcp-server` | Free | 9/10 |
| **MCP Inspector** (Anthropic) | Тест MCP серверов | `npx @modelcontextprotocol/inspector` | Free | 9/10 |
| **Nuclei MCP** | Vulnerability scan | `npx nuclei-mcp` | Free | 9/10 |
| **@playwright/mcp** (Microsoft) | E2E тесты | уже подключён ✅ | Free | 9/10 |
| **AWS Security Scanner** | Python/IaC scan | Python server | Free | 8/10 |
| **Burp Suite + AI** | HTTP proxy AI | SSE server | Free/Pro | 10/10 |
| **@executeautomation/playwright-mcp** | E2E + API тест | `npx @executeautomation/playwright-mcp-server` | Free | 8/10 |
| **ReportPortal** (в mcpservers) | Test results analysis | В реестре MCP | Free/Cloud | 7/10 |

---

## ЧТО УСТАНАВЛИВАЕМ ПРЯМО СЕЙЧАС

### Приоритет 1 (сегодня)
```bash
# Semgrep — сканируем код целей на уязвимости
claude mcp add --scope user semgrep -- npx -y semgrep-mcp

# Chrome DevTools — дебаггим веб-приложения
claude mcp add --scope user chrome-devtools -- npx -y @chrome-devtools/mcp-server
```

### Приоритет 2 (после Burp установки)
```bash
# Nuclei MCP — запускаем шаблоны прямо из Claude
claude mcp add --scope user nuclei -- npx -y nuclei-mcp
```

### Приоритет 3 (для ivrit-ai-pro разработки)
```bash
# MCP Inspector — тестируем наш mcp_bridge сервер
npx @modelcontextprotocol/inspector
```

---

## КАК ЭТО МЕНЯЕТ BUG BOUNTY ПРОЦЕСС

### До (вручную):
```
Читаю код → нахожу что-то подозрительное → пишу PoC вручную → тестирую curl
```

### После (с MCP стеком):
```
Semgrep MCP → автоматически находит уязвимые паттерны в коде цели
     ↓
Nuclei MCP → проверяет уязвимость по шаблону
     ↓
Playwright/Chrome DevTools MCP → E2E доказательство эксплуатации
     ↓
Claude → пишет репорт с PoC → отправляет на huntr.com
```

---

## НОВИНКИ 2025-2026

| Новинка | Что нового |
|---------|-----------|
| **Semgrep MCP** | Официальная интеграция с Claude Code marketplace |
| **Chrome DevTools MCP** | Google официально выпустили в 2025, Node 22+ |
| **Burp Suite MCP** | PortSwigger добавили MCP в 2025 — революция для pentest |
| **Nuclei AI templates** | AI генерирует Nuclei templates автоматически |
| **n8n + Nuclei workflow** | Автоматический ежедневный CVE скан bug bounty программ |

---

## ДОПОЛНИТЕЛЬНЫЕ РЕСУРСЫ

- **awesome-cybersecurity-agentic-ai**: https://github.com/raphabot/awesome-cybersecurity-agentic-ai
  Полный список security MCP серверов: BloodHound MCP, SQLMap MCP, и другие

- **Penligent.ai guide 2026**: Practical bug bounty stack — Burp Suite + ProjectDiscovery + Nuclei + AI

- **n8n workflow**: Автоматический CVE скан bug bounty программ через Nuclei + email отчёт

---

*Исследование проведено: 2026-03-23 | Brave Search*
