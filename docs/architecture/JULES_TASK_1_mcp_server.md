# Jules Task 1 — MCP Security Server

## Цель
Написать MCP (Model Context Protocol) сервер на Python, который даёт Claude инструменты для security тестирования прямо в диалоге.

## Файл
`/Users/rodion/projects/security-empire/mcp-server/server.py`

## Стек
- Python 3.14
- `mcp` пакет (pip install mcp)
- `httpx` для HTTP запросов
- `PyJWT` для анализа токенов
- `asyncio`

## Инструменты (tools) которые нужно реализовать

### 1. `map_endpoints(base_url: str) -> list`
Делает GET на популярные пути и возвращает список тех, что отвечают без auth:
```
/health, /metrics, /docs, /openapi.json, /routes, /debug, /admin,
/v1/models, /user/list, /key/list, /config, /.env, /api/v1/...
```
Возвращает: `[{"path": "/health", "status": 200, "auth_required": false}]`

### 2. `test_cors(base_url: str, paths: list = None) -> dict`
Для каждого endpoint делает OPTIONS с `Origin: https://evil.example.com`:
- Проверяет отражается ли Origin в `Access-Control-Allow-Origin`
- Проверяет `Access-Control-Allow-Credentials: true`
- Детектирует wildcard `*` + credentials комбо
Возвращает: `{"vulnerable": bool, "details": [...]}`

### 3. `check_jwt(token: str) -> dict`
Анализирует JWT без проверки подписи:
- Декодирует header + payload
- Проверяет наличие `exp` claim (нет exp = уязвимость)
- Проверяет алгоритм (none = критично, HS256 с пустым ключом = критично)
- Ищет в payload: `key`, `api_key`, `password`, `secret`, `token`
- Проверяет `httponly` (если есть set-cookie)
Возвращает: `{"issues": [...], "payload": {...}, "severity": "high|medium|low"}`

### 4. `test_auth_bypass(base_url: str, paths: list) -> list`
Пробует каждый path:
- Без Authorization заголовка
- С пустым Bearer: `Authorization: Bearer `
- С null: `Authorization: Bearer null`
- С `Authorization: Bearer invalid`
Возвращает список путей где получили НЕ 401/403.

### 5. `test_rate_limit(url: str, method: str = "GET", n: int = 50) -> dict`
Делает N запросов подряд и замечает:
- Когда (если) начинают приходить 429
- Среднее время ответа
- Был ли заголовок `X-RateLimit-*`
Возвращает: `{"rate_limited": bool, "limit_hit_at": int, "avg_ms": float}`

### 6. `extract_jwt_from_login(base_url: str, username: str, password: str) -> dict`
Делает POST /v2/login или /auth/login с credentials,
извлекает JWT из set-cookie или response body,
вызывает check_jwt() на полученный токен.
Возвращает полный анализ.

### 7. `test_logout(base_url: str) -> dict`
Проверяет существование logout endpoint:
- GET/POST /logout, /signout, /auth/logout, /v1/logout, /api/logout
- После logout старый токен всё ещё работает?
Возвращает: `{"logout_exists": bool, "token_invalidated": bool}`

## MCP сервер структура
```python
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("security-tools")

@server.tool()
async def map_endpoints(base_url: str) -> str:
    ...

# и т.д. для каждого инструмента
```

## Запуск
```bash
python mcp-server/server.py
```

## Конфиг для Claude (~/.claude/claude_desktop_config.json)
```json
{
  "mcpServers": {
    "security-tools": {
      "command": "python3",
      "args": ["/Users/rodion/projects/security-empire/mcp-server/server.py"]
    }
  }
}
```

## Требования к коду
- Весь async/await
- Таймауты на все HTTP запросы (5 сек)
- Обработка ошибок — никогда не крашиться
- Логирование в stderr (не stdout — он занят MCP протоколом)
- Комментарии на русском языке
