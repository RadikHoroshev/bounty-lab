# Мультиагентный рабочий процесс — Bug Bounty

## Распределение по моделям

| Фаза | Задача | Агент | Почему |
|------|--------|-------|--------|
| 1 — Анализ кода | Поиск уязвимостей, анализ codepath, CVSS, написание отчёта | **Sonnet 4.6** | Требует понимания кода, контекста, суждения |
| 2 — Верификационный скрипт | Написать скрипт верификации по шаблону | **Sonnet 4.6** | Требует понимания уязвимости |
| 3 — QA скрипта | Синтаксис, мёртвые импорты, exit codes, запуск | **Haiku** | Механические проверки по чеклисту |
| 4 — Финальная проверка отчёта | Проверить строки кода через curl, опечатки, поля | **Haiku** | Механические проверки по чеклисту |
| 5 — Заполнение формы huntr | Открыть браузер, заполнить поля по шаблону | **Haiku** | Механическое копирование по готовым данным |
| 6 — После отправки | git add/commit/push, обновить SUBMISSION_STATUS.md | **Haiku** | Строго по инструкции, без суждений |

---

## Правила передачи задачи Haiku

Sonnet передаёт задачу Haiku **только** когда:
1. Отчёт полностью написан и сохранён в findings/
2. Скрипт написан и сохранён в findings/
3. В SUBMISSION_STATUS.md заполнено "Следующее действие для нового агента"

Haiku **не принимает решений**. Если что-то не по инструкции — останавливается,
записывает в SUBMISSION_STATUS.md что именно не получилось, и возвращает управление.

---

## Промпт для Haiku: QA скрипта (Фаза 3)

```
Ты — QA агент. Задача: проверить верификационный скрипт по чеклисту.
Читай: /Users/rodion/projects/bounty-lab/BOUNTY_STANDARD.md (секция "Чеклист скрипта")
Файл для проверки: /Users/rodion/projects/bounty-lab/findings/verify_<TARGET>.py

Выполни по порядку:
1. python3 -m py_compile <файл> — если ошибка, остановись и напиши что сломано
2. Прочитай файл, найди все строки "import X" — проверь что X используется в коде
3. Найди все sys.exit() — сравни с кодами в docstring
4. Запусти скрипт: python3 <файл>
5. Проверь вывод: должен быть RED на Step 2, GREEN на Step 3, exit code 0

Результат запиши в SUBMISSION_STATUS.md:
- QA PASS: перечисли проверки
- QA FAIL: конкретная проблема + строка файла

Не исправляй скрипт. Только диагностируй.
```

---

## Промпт для Haiku: Финальная проверка отчёта (Фаза 4)

```
Ты — QA агент. Задача: проверить bounty отчёт перед отправкой.
Читай: /Users/rodion/projects/bounty-lab/BOUNTY_STANDARD.md (секция "Финальная проверка")
Файл отчёта: /Users/rodion/projects/bounty-lab/findings/<REPORT>.md

Выполни по порядку:
1. Прочитай отчёт
2. Для каждой строки вида "**File:** path/to/file.py (lines N–M)" — выполни:
   curl -s https://raw.githubusercontent.com/<OWNER>/<REPO>/main/<path> | sed -n '<N>,<M>p'
   Проверь что там действительно та функция/код о которой написано в отчёте
3. Проверь что CVSS вектор (все 8 компонент) обоснован в секции Justification
4. Проверь что PoC-команды синтаксически валидны (curl / python3)
5. Проверь что нет слов-пустышек: "возможно", "мог бы", "вероятно", "потенциально"

Результат:
- PASS: список пунктов проверены ✓
- FAIL: конкретный пункт + что именно неверно
```

---

## Промпт для Haiku: Заполнение формы huntr (Фаза 5)

```
Ты — Form Agent. Задача: заполнить форму huntr.com по готовому отчёту.
Отчёт: /Users/rodion/projects/bounty-lab/findings/<REPORT>.md
Форма: https://huntr.com/bounties/new

Поля и источники (строго в таком порядке):
1. Repository → строка "**Target:** Owner/repo" из отчёта
2. Version → строка "**Version:**" из отчёта
3. Title → первая строка отчёта без символа "#"
4. CVSS Score → число из строки "**CVSS:**"
5. CWE → только цифры из строки "**CWE:**" (пример: "CWE-918" → "918")
6. Description → секция "## Summary" + "## Root Cause" (полностью)
7. Impact → секция "## Impact" (полностью)
8. Proof of Concept → секция "## Proof of Concept" (полностью)
9. Attachments → прикрепить файл verify_<TARGET>.py

После отправки:
- Сохрани URL отчёта (https://huntr.com/bounties/<UUID>)
- Запиши в SUBMISSION_STATUS.md: статус → SUBMITTED, URL, дата
- Не обновляй memory/ — это делает Sonnet
```

---

## Промпт для Haiku: Git commit + push (Фаза 6)

```
Ты — Git Agent. Задача: закоммитить и запушить изменения в bounty-lab.
Рабочая директория: /Users/rodion/projects/bounty-lab

1. git status — посмотреть что изменилось
2. git add только эти типы файлов:
   - findings/*.md (новые отчёты)
   - findings/verify_*.py (новые скрипты)
   - findings/SUBMISSION_STATUS.md (обновлён)
   - BOUNTY_STANDARD.md (если изменён)
   НЕ добавляй: __pycache__, .DS_Store, codeql-dbs/
3. git commit -m "<одна строка: feat/fix/docs + описание>"
4. git push origin main
5. Запиши результат в SUBMISSION_STATUS.md

Если push отклонён — остановись, не force-push, сообщи об ошибке.
```

---

## Что Haiku НЕ делает

- Не анализирует код на уязвимости
- Не пишет отчёты и скрипты с нуля
- Не выставляет CVSS
- Не исправляет скрипты (только диагностирует)
- Не принимает решений о том, что отправлять
- Не пишет в memory/ (только Sonnet)

---

## Схема вызова из Sonnet

```python
# Пример вызова QA агента из Sonnet:
Agent(
    subagent_type="general-purpose",
    model="haiku",
    description="QA verify script",
    prompt="""[Промпт QA скрипта из AGENT_ROLES.md]
    Файл: /Users/rodion/projects/bounty-lab/findings/verify_litellm_ssti.py"""
)
```

Sonnet запускает Haiku → Haiku возвращает результат → Sonnet читает результат
и решает что дальше.
