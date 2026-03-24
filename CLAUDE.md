# Bug Bounty Lab — Инструкции для агента

## Первое действие при входе в репозиторий

Прочитай два файла:
1. `BOUNTY_STANDARD.md` — стандарт отчёта, верификационного скрипта, 3-stage проверки
2. `findings/SUBMISSION_STATUS.md` — текущее состояние всех репортов

Затем действуй согласно статусу без вопросов.

---

## Роли агентов

| Задача | Агент |
|--------|-------|
| Анализ кода, написание отчёта, CVSS | **Sonnet 4.6** |
| Верификационный скрипт + TEST PLAN | **Sonnet 4.6** |
| Stage 1 (проверка кода через curl) | **Haiku / Qwen** |
| Stage 2 (слепое тестирование) | **Haiku / Qwen** |
| Stage 3 (финальный аппрув) | **Sonnet 4.6** |
| Заполнение формы huntr | `submit_to_huntr.py` → Haiku / Qwen |
| git commit/push | **Haiku / Qwen** |

Подробные промпты для каждой фазы → `AGENT_ROLES.md`

---

## Структура репозитория

```
bounty-lab/
├── CLAUDE.md                  ← этот файл
├── BOUNTY_STANDARD.md         ← стандарт качества (читать обязательно)
├── AGENT_ROLES.md             ← роли и промпты агентов
├── verify_template.py         ← шаблон для новых verify_*.py
├── submit_to_huntr.py         ← авtozаполнение формы huntr из MD
├── findings/
│   ├── SUBMISSION_STATUS.md   ← статус всех репортов (читать при входе)
│   ├── SCRIPT_AUDIT_LOG.md    ← лог аудита скриптов
│   ├── TEST_PLAN_*.md         ← тест-планы для Stage 2
│   ├── STAGE1_RESULT_*.md     ← результаты Stage 1
│   ├── STAGE2_RESULT_*.md     ← результаты Stage 2
│   ├── verify_*.py            ← верификационные скрипты
│   └── *.md                   ← отчёты
└── knowledge/                 ← база знаний по уязвимостям
```

---

## Процесс: находка → отправка

```
Фаза 1  [Sonnet]   Отчёт по шаблону BOUNTY_STANDARD.md
Фаза 2  [Sonnet]   verify_*.py + TEST_PLAN_*.md
─────────────────────────────────────────────────
Фаза 3  [Haiku]    STAGE 1 — проверка file:line через curl
Фаза 4  [Haiku]    STAGE 2 — слепое тестирование по TEST PLAN
Фаза 5  [Sonnet]   STAGE 3 — сверка фактов, APPROVED / BLOCKED
─────────────────────────────────────────────────
Фаза 6  [Haiku]    python3 submit_to_huntr.py report.md --submit
Фаза 7  [Haiku]    git add findings/ && git commit && git push
Фаза 8  [Haiku]    Проверка отправленного отчёта на huntr
Фаза 9  [Sonnet]   Обновление memory/
```

**Отправка без прохождения Stage 1 → 2 → 3 запрещена.**

---

## Инструменты

```bash
# Новый verify_*.py — скопировать шаблон
cp verify_template.py findings/verify_<target>_<type>.py

# Проверить что отчёт распарсится правильно
python3 submit_to_huntr.py findings/report.md

# Отправить на huntr
python3 submit_to_huntr.py findings/report.md --submit

# Установить Playwright (если не установлен)
pip install playwright && playwright install chromium
```

---

## Правила

- Каждое утверждение в отчёте подкреплено кодом или выводом скрипта
- Нет слов: "возможно", "вероятно", "мог бы", "потенциально"
- Verified Output в отчёте — дословный вывод с терминала, не придуманный
- CVSS в баннере скрипта = CVSS в отчёте = CVSS в форме huntr
- Permalink в Occurrences — конкретный SHA, не main/HEAD
- Haiku/Qwen не анализируют, не пишут отчёты, не исправляют скрипты

---

## Целевые репозитории (приоритет)

| Репозиторий | Статус | Bounty |
|-------------|--------|--------|
| `BerriAI/litellm` | 5 репортов pending | до $1500 |
| `ollama/ollama` | 2 репорта pending | $750 ea |
| `open-webui/open-webui` | 2 репорта pending | до $1500 |
| `mlflow/mlflow` | 37 semgrep findings | до $1500 |
| `nltk/nltk` | 1 репорт pending | $125-175 |

Следующая цель: MLflow или новые AI/ML репозитории на huntr.com.
