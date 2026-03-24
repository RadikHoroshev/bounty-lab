# Script Audit Log — Verification Scripts Quality Review

Дата аудита: 2026-03-24
Аудитор: Claude Code (claude-sonnet-4-6)
Область: все `verify_*.py` в `/findings/`

---

## Методология

Для каждого скрипта проверялось:
1. Синтаксис: `python3 -m py_compile`
2. Неиспользуемые импорты: ручной анализ + AST-парсинг
3. Exit codes: соответствие docstring и реализации
4. Docstring: полнота требований к окружению
5. Запуск: фактический вывод совпадает с ожидаемым

---

## verify_litellm_ssti.py

**Статус после аудита:** ✅ Исправлен

### Найденные ошибки

#### BUG-SSTI-01 — Мёртвый импорт `subprocess`
- **Тип:** Dead code
- **Строка до исправления:** `18: import subprocess`
- **Проблема:** модуль `subprocess` нигде не используется в коде скрипта
- **Риск:** вводит в заблуждение читателя, намекает на вызов subprocess там, где его нет
- **Исправление:** строка удалена
- **Статус:** ✅ Исправлено

#### BUG-SSTI-02 — Неразличимые exit codes для разных исходов
- **Тип:** Logic error
- **Строки до исправления:**
  ```python
  # строка 165 — уязвимость подтверждена
  sys.exit(0)
  # строка 168 — уязвимость НЕ воспроизведена
  sys.exit(0)
  ```
- **Проблема:** оба исхода (подтверждено / не воспроизведено) возвращали `exit(0)`.
  Docstring заявлял: "0 — vulnerability confirmed", что было технически ложью
  для второго пути. Автоматизированный вызов скрипта не мог различить результаты.
- **Исправление:** путь "не воспроизведено" изменён на `sys.exit(2)`
- **Новые exit codes:**
  - `0` — уязвимость подтверждена (RCE воспроизведён)
  - `1` — ошибка зависимости или arithmetic test провалился
  - `2` — не воспроизведено (возможно уже исправлено)
- **Статус:** ✅ Исправлено

#### BUG-SSTI-03 — Неполный docstring: условия запуска
- **Тип:** Documentation gap
- **Строки до исправления:**
  ```
  Requirements: pip install jinja2
  No running LiteLLM instance needed — tests the root cause directly.
  ```
- **Проблема:** не указана минимальная версия Python, не указана минимальная версия
  jinja2 (функция `namespace()` добавлена в jinja2 2.10 — на более старых версиях
  payload упадёт с `UndefinedError`), не указано что сетевой доступ не нужен
- **Исправление:** docstring заменён:
  ```
  Requirements:
    - Python 3.8+
    - jinja2 >= 2.10  (pip install jinja2)

  No running LiteLLM instance needed — tests the Jinja2 environment directly.
  No network access required.
  ```
- **Статус:** ✅ Исправлено

### Проверка после исправлений

```
$ python3 -m py_compile verify_litellm_ssti.py  → OK
$ python3 verify_litellm_ssti.py
  [1/3] 7*7 = 49   → GREEN ✓
  [2/3] RCE: uid=501(rodion)...  → RED [VULNERABLE]
  [3/3] Fix: SecurityError blocked  → GREEN [FIXED]
  exit code: 0
```

---

## verify_litellm_ssrf.py

**Статус после аудита:** ✅ Исправлен

### Найденные ошибки

#### BUG-SSRF-01 — Мёртвый импорт `socket`
- **Тип:** Dead code
- **Строка до исправления:** `29: import socket`
- **Проблема:** модуль `socket` нигде не используется. Предположительно планировалась
  проверка доступности порта 18877 перед запуском capture server, но реализована
  не была.
- **Исправление:** строка удалена
- **Статус:** ✅ Исправлено

#### BUG-SSRF-02 — Docstring не описывал условия работы Step 3
- **Тип:** Documentation gap
- **Проблема:** docstring указывал только что нужен LiteLLM proxy. Не было указано,
  что Step 3 (проверка фикса `is_safe_url`) работает автономно без прокси,
  и что порт 18877 должен быть свободен.
- **Риск:** Человек без работающего LiteLLM мог отказаться от запуска скрипта,
  не зная что Step 3 доступен независимо.
- **Исправление:** добавлены секции `Note:` и явное указание порта:
  ```
  - Port 18877 must be free (capture server)

  Note:
    Step 1 and 2 require a running LiteLLM proxy.
    Step 3 (fix validator) runs without any proxy — tests pure Python logic.
  ```
- **Статус:** ✅ Исправлено

### Нерешённые замечания (minor, некритично)

#### NOTE-SSRF-01 — Нет проверки доступности порта 18877
- **Тип:** Robustness
- **Проблема:** если порт 18877 занят другим процессом, `HTTPServer.__init__` бросит
  `OSError: [Errno 48] Address already in use` без понятного сообщения.
  Чистая обработка: `socket.socket().connect_ex(('127.0.0.1', 18877)) == 0`
  до старта сервера.
- **Решение:** не реализовано — изменение логики выходит за рамки аудита
- **Документировано:** в docstring добавлено "Port 18877 must be free"

---

## verify_ollama_ssrf.py

**Статус после аудита:** ✅ Без изменений (только документирование)

### Найденные замечания

#### NOTE-OLLAMA-01 — Нет проверки версии Ollama на поддержку OLLAMA_CLOUD_BASE_URL
- **Тип:** Compatibility
- **Проблема:** переменная `OLLAMA_CLOUD_BASE_URL` появилась в Ollama 0.18.x.
  На более старых версиях скрипт запустится, но capture server не получит запросов,
  что будет выглядеть как "не воспроизведено".
- **Решение:** не реализовано — версия явно указана в affected range (≤ 0.18.2)
- **Документировано:** в docstring уже указано `ollama/ollama ≤ 0.18.2`

#### NOTE-OLLAMA-02 — Порты 19877 и 11435 без проверки занятости
- **Тип:** Robustness
- **Аналогично NOTE-SSRF-01** — при занятом порте ошибка без понятного сообщения
- **Документировано:** docstring уже указывает порты явно

---

## Итоговая таблица

| Скрипт | Баги найдено | Исправлено | Замечания (minor) |
|--------|-------------|------------|-------------------|
| `verify_litellm_ssti.py` | 3 | 3 | 0 |
| `verify_litellm_ssrf.py` | 2 | 2 | 1 |
| `verify_ollama_ssrf.py` | 0 | 0 | 2 |
| **Итого** | **5** | **5** | **3** |

Все критические ошибки устранены. Minor замечания задокументированы, не влияют
на корректность вывода скриптов при нормальных условиях.

---

## Команды для воспроизведения аудита

```bash
# Синтаксис
for f in verify_litellm_ssti.py verify_litellm_ssrf.py verify_ollama_ssrf.py; do
  python3 -m py_compile findings/$f && echo "$f: OK"
done

# Запуск SSTI (не нужен LiteLLM)
python3 findings/verify_litellm_ssti.py
echo "Exit: $?"  # ожидается 0

# Запуск SSRF (Step 3 без LiteLLM — тест валидатора)
python3 -c "
exec(open('findings/verify_litellm_ssrf.py').read())
step3_fix()
"
```
