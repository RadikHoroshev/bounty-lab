# Стандарт составления bug bounty отчёта

> **Для нового агента:** читай этот файл и `SUBMISSION_STATUS.md`.
> Продолжай с первого пункта в статусе "READY" — без вопросов.

---

## Принципы

- Отчёт — инженерный документ. Никаких вводных фраз, эпитетов, догадок.
- Каждое утверждение подкреплено кодом, строкой файла или выводом скрипта.
- Все утверждения о воздействии сформулированы как факты, а не возможные последствия.
- Верификационный скрипт — обязательный артефакт наравне с отчётом.
- Перед отправкой — обязательная трёхступенчатая проверка (Stage 1 → 2 → 3).

---

## Структура отчёта (шаблон)

```
# <ТИП УЯЗВИМОСТИ> via <ВЕКТОР> in <target/repo>

**Target:** Owner/repo
**Version:** ≤ X.Y.Z
**CVSS:** N.N <Severity> (AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_)
**CWE:** CWE-NNN: <Name>
**Date:** YYYY-MM-DD

---

## Summary
[1 параграф: что уязвимо, каким образом, что может сделать атакующий]

---

## Exploitation
- **Privileges required:** <роль или "none">
- **Steps to exploit:** <число HTTP-запросов / действий>
- **Special conditions:** <"none" или конкретное условие>
- **Tested on:** <версия target, Python X.Y, OS>

---

## Root Cause
**File:** path/to/file.py (lines N–M)
[Фрагмент кода — только уязвимые строки с inline-комментарием]

---

## Minimal Reproduction
[Одна команда — нейтральный тест без деструктивного эффекта]
# Expected output: <конкретный вывод подтверждающий уязвимость>

---

## Proof of Concept
### Setup
[Минимальная команда для запуска тестовой среды]

### Exploit
[Полный curl/скрипт, подтверждающий уязвимость]

### Verified Output
[Дословный вывод с реального запуска — не придуманный]
```
uid=501(rodion) gid=20(staff)...   ← пример для RCE
{"error":"captured"}               ← пример для SSRF
```

---

## Fix
### Before (vulnerable)
[Уязвимый код]

### After (fixed)
[Исправленный код]

Apply to: [список всех файлов где нужно изменение]

---

## Detection
- **Log evidence:** <что появится в логах при эксплуатации, или "none by default">
- **SIEM indicator:** <паттерн для детектирования, или "N/A">

---

## Impact
| Scenario | Risk |
|----------|------|
| ...      | ...  |

---

## Vulnerable Code Locations
| File | Function | Line | Issue |
|------|----------|------|-------|
| ...  | ...      | ...  | ...   |

---

## CVSS Score Justification
**CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_ = N.N**
- **AV:N** — <обоснование>
- **AC:L** — <обоснование>
- **PR:L** — <обоснование>
- **UI:N** — <обоснование>
- **S:C** — <обоснование>
- **C:H** — <обоснование>
- **I:_** — <обоснование>
- **A:_** — <обоснование>

---

## Relationship to Existing CVEs
[Если нет похожих CVE: "No prior CVE covers this endpoint/codepath."]
[Если есть: таблица сравнения — endpoint, code, trigger, scope]
```

---

## Стандарт верификационного скрипта

Файл: `verify_<target>_<type>.py`

### Требования

1. **Docstring**: требования к окружению, exit codes, как запустить каждый сценарий
2. **Зависимости**: только stdlib + минимум внешних (с обработкой ImportError → exit 1)
3. **Три шага**:
   - `[STEP 1]` Sanity check — цель доступна (иначе exit 1)
   - `[STEP 2]` Exploit — уязвимость подтверждена (RED = уязвим)
   - `[STEP 3]` Fix — предложенный фикс блокирует (GREEN = исправлен)
4. **Exit codes**: `0` = уязвимо, `1` = окружение недоступно, `2` = не воспроизведено
5. **Capture server** (если нужен): `CAPTURE_URL` должен указывать на тот же порт что и `CAPTURE_PORT`
6. **Никаких побочных эффектов**: не изменяет файлы, не делает запросов кроме localhost
7. **Цвета**: RED = уязвимо, GREEN = исправлено, YELLOW = неизвестно

### TEST PLAN — шаблон

Создаётся вместе со скриптом. Передаётся независимому тестировщику без объяснений.

```markdown
## TEST PLAN — verify_<target>_<type>.py

### Requirements
- Install: <pip install ...>
- Vulnerable service: <команда запуска>
- Patched service: <команда / "N/A">

### Scenario A — no dependencies
1. Убедиться что сервис не запущен
2. python3 verify_X.py
3. Записать: exit code + первые 5 строк stdout

### Scenario B — service up, not vulnerable
1. <запустить исправленный сервис>
2. python3 verify_X.py
3. Записать: exit code + весь вывод

### Scenario C — service up, vulnerable
1. <запустить уязвимый сервис>
2. python3 verify_X.py
3. Записать: exit code + весь вывод

### Capture check (если есть capture server)
- CAPTURE_PORT в коде: ?
- CAPTURE_URL в коде: ?
- Совпадает ли порт: ?
- Запросов захвачено в Scenario C: ?
```

---

## Трёхступенчатая проверка перед отправкой

```
┌─────────────────────────────────────────────────────────┐
│  STAGE 1 — Проверка кода и отчёта        [HAIKU]        │
│  STAGE 2 — Независимое тестирование скрипта [HAIKU/QWEN]│
│  STAGE 3 — Финальный аппрув              [SONNET]        │
└─────────────────────────────────────────────────────────┘
         Все три PASS → Submission разрешена
```

### STAGE 1 — Проверка кода и отчёта `[HAIKU]`

Агент читает отчёт и проверяет каждый факт. Не анализирует — только верифицирует.

```
[ ] Все строки вида "File: path/to/file.py (lines N–M)":
    → curl https://raw.githubusercontent.com/<OWNER>/<REPO>/main/<path> | sed -n 'N,Mp'
    → содержимое совпадает с описанием в отчёте

[ ] Все permalink URL в Occurrences:
    → curl -I <URL> → HTTP 200 (не 404)

[ ] Minimal Reproduction команда синтаксически валидна:
    → bash -n <команда> или python3 -c "compile(...)"

[ ] Нет слов-пустышек: "возможно", "мог бы", "вероятно", "потенциально"

[ ] CVSS: все 8 компонент заполнены в Justification

[ ] Секция "Exploitation" заполнена (privileges, steps, conditions, tested on)

[ ] Секция "Detection" заполнена

[ ] Секция "Relationship to Existing CVEs" заполнена

Результат → SUBMISSION_STATUS.md: STAGE1 PASS / FAIL + список что не прошло
```

### STAGE 2 — Независимое тестирование скрипта `[HAIKU/QWEN]`

Агент получает TEST PLAN и скрипт. **Не знает какие ошибки ожидаются.**
Возвращает только факты: exit code, дословный вывод, захваты.

```
[ ] Scenario A (no deps): exit code = ?  stdout первые 5 строк = ?
[ ] Scenario C (vulnerable): exit code = ?  stdout = ?
[ ] Capture check: CAPTURE_PORT = ?  CAPTURE_URL = ?  захватов = ?

Ожидаемые результаты (заполняет Sonnet заранее в TEST PLAN):
- Scenario A → exit 1
- Scenario C → exit 0
- Capture (если есть) → ≥1 запрос захвачен

Расхождение факта с ожидаемым = баг → Sonnet фиксит → повтор STAGE 2
```

### STAGE 3 — Финальный аппрув `[SONNET]`

Sonnet читает результаты STAGE 1 и STAGE 2. Принимает решение об отправке.

```
[ ] STAGE 1 PASS
[ ] STAGE 2: все сценарии вернули ожидаемые exit codes
[ ] STAGE 2: capture server захватил ≥1 запрос (если применимо)
[ ] CVSS в скрипте (баннер) == CVSS в отчёте == CVSS в форме huntr
[ ] Нет расхождений между file paths в тексте и в Occurrences permalink

→ APPROVED: переходить к заполнению формы
→ BLOCKED: описать что именно, вернуть в Фазу 1 или 2
```

---

## Процесс: от находки до отправки

```
Фаза 1  [SONNET]       Отчёт + TEST PLAN
Фаза 2  [SONNET]       Верификационный скрипт
──────────────────────────────────────────────
Фаза 3  [HAIKU]        STAGE 1: проверка кода и отчёта
Фаза 4  [HAIKU/QWEN]   STAGE 2: независимое тестирование (вслепую)
Фаза 5  [SONNET]       STAGE 3: финальный аппрув
──────────────────────────────────────────────
Фаза 6  [HAIKU]        Заполнение формы huntr
Фаза 7  [HAIKU]        Git commit + push
Фаза 8  [HAIKU]        Проверка отправленного отчёта на huntr
Фаза 9  [SONNET]       Обновление memory
```

Промпты для каждой фазы — в `AGENT_ROLES.md`.

---

## Инструменты (автоматизация)

| Файл | Назначение | Использование |
|------|-----------|---------------|
| `verify_template.py` | Шаблон для новых verify_*.py | Скопировать, заполнить CONFIG-блок |
| `submit_to_huntr.py` | Автозаполнение формы huntr из MD | `python3 submit_to_huntr.py report.md --submit` |

### submit_to_huntr.py

```bash
# Dry-run — проверить что распарсится
python3 submit_to_huntr.py findings/report.md

# Реальная отправка (браузер Chrome)
python3 submit_to_huntr.py findings/report.md --submit

# Headless
python3 submit_to_huntr.py findings/report.md --submit --headless
```

**Требования:** `pip install playwright && playwright install chromium`

**Парсит из отчёта автоматически:**
- `**Target:** Owner/repo` → GitHub URL + определяет package_manager
- `**Version:**` → affected version
- `**CVSS:**` → score + 8 CVSS-кнопок
- `**CWE:** CWE-NNN: Name` → vulnerability type (React-select)
- `## Summary` + `## Root Cause` → Description
- `## Impact` → Impact
- `## Vulnerable Code Locations` → Occurrences (или ищет GitHub permalink в тексте)

**Стабильные field ID обнаружены 2026-03-24:**
`#target-url`, `#package-select`, `#version-select`, `#react-select-5-input`, `#write-up-title`, `#readmeProp-input`, `#impactProp-input`, `#permalink-url-N`, `#description-N`

---

## Условия запуска скриптов

| Скрипт | Требует | Не требует |
|--------|---------|-----------|
| `verify_litellm_ssti.py` | Python 3.8+, jinja2 ≥ 2.10 | LiteLLM, сеть, API ключи |
| `verify_litellm_ssrf.py` | Python 3.8+, requests, LiteLLM на :4000, порт 18877 | сеть кроме localhost |
| `verify_ollama_ssrf.py` | Python 3.8+, ollama binary, порты 19877 и 11435 | сеть кроме localhost |

---

## Чеклист передачи между агентами

```
## ТЕКУЩЕЕ СОСТОЯНИЕ (обновлено: YYYY-MM-DD HH:MM)
- Активная задача: [что делается]
- Остановились на: Фаза N / Stage N
- Сделано: [список]
- Осталось: [список]
- Следующее действие: [одна команда или действие — без вопросов]
```

---

## Ошибки которые нельзя допускать

- File:line в отчёте не проверен через `curl raw.githubusercontent.com`
- Verified Output в отчёте придуман, а не скопирован с терминала
- Capture server в скрипте слушает на порту X, но тест шлёт на порт Y
- CVSS в баннере скрипта не совпадает с CVSS в форме
- Отправка без прохождения всех трёх Stage
- Слова "возможно", "вероятно", "может быть" в любом разделе отчёта
- Неиспользуемые import в скрипте
- Exit code 1 вместо 2 для "не воспроизведено"
- Permalink в Occurrences ведёт на main/HEAD вместо конкретного SHA коммита
