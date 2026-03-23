# Jules Task 3 — Auto-Recon Pipeline

## Цель
Единый скрипт который по git URL цели автоматически проводит полный security audit
и генерирует отчёт с приоритизированными находками.

## Файл
`/Users/rodion/projects/security-empire/recon/recon.py`

## Запуск
```bash
# Скан конкретного репо
python3 recon/recon.py https://github.com/BerriAI/litellm

# Скан с живым инстансом
python3 recon/recon.py https://github.com/BerriAI/litellm --url http://localhost:4000 --key sk-1234

# Скан всех целей из targets/
python3 recon/recon.py --all
```

## Pipeline шаги

### Шаг 1: Clone & Setup (2 мин)
```python
git clone REPO /tmp/recon/REPO_NAME
```

### Шаг 2: Static Analysis (5 мин)
Запускает `semgrep --config auto` + кастомные паттерны:

```python
SECURITY_PATTERNS = [
    # JWT уязвимости
    r'jwt\.encode\([^)]*\)',           # JWT без exp
    r'set_cookie\([^)]*\)',            # cookie без httponly
    r'allow_credentials=True',         # CORS credentials
    r'allow_origins=\["\*"\]',         # wildcard CORS

    # Секреты в коде
    r'(password|secret|api_key)\s*=\s*["\'][^"\']{8,}',

    # Опасные функции
    r'subprocess\..*shell=True',       # RCE риск
    r'eval\(',                         # code injection
    r'pickle\.loads',                  # deserialization
    r'yaml\.load\(',                   # unsafe YAML

    # SQL injection
    r'execute\(f["\']',               # f-string в SQL
    r'\.format\(.*\)\)',              # format в SQL

    # Path traversal
    r'open\(.*\+',                    # конкатенация в path
    r'os\.path\.join\(.*request\.',   # user input в path
]
```

### Шаг 3: Dynamic Analysis (если --url передан)
```python
# Маппинг endpoints
endpoints = map_endpoints(base_url)

# CORS проверка
cors_results = test_cors(base_url, endpoints)

# Auth bypass проверка
bypass_results = test_auth_bypass(base_url, endpoints)

# JWT анализ (если есть login)
jwt_results = extract_jwt_from_login(base_url, "admin", master_key)

# Rate limit
rate_results = test_rate_limit(f"{base_url}/health")
```

### Шаг 4: Nuclei Scan (если установлен)
```bash
nuclei -u BASE_URL -t nuclei-templates/ -t ~/.nuclei-templates/
```

### Шаг 5: Report Generation

Генерирует `/reports/REPO_NAME_YYYY-MM-DD.md`:

```markdown
# Security Report: litellm v1.82.6
Date: 2026-03-23
Duration: 8m 32s

## Summary
- 🔴 Critical: 1
- 🟠 High: 2
- 🟡 Medium: 3
- 🔵 Low: 5

## Findings

### 🔴 [CRITICAL] RCE via subprocess shell=True
File: litellm/proxy/skills/main.py:248
Code: `subprocess.run(cmd, shell=True)`
CVSS: 9.8
CWE: CWE-78
Huntr ready: YES

### 🟠 [HIGH] JWT без expiry claim
...

## Рекомендуемые следующие шаги
- [ ] Проверить вручную: litellm/proxy/skills/main.py:248
- [ ] Написать PoC для RCE
- [ ] Отправить на huntr

## Сырые данные
[полные результаты всех сканеров]
```

## Требования
- Весь async где возможно
- Прогресс-бар в stdout (rich или tqdm)
- Таймаут на весь pipeline: 30 минут
- Сохранять частичные результаты если прервано
- Дедупликация: не включать уже известные finding'и (читать targets/REPO.yaml)
- Комментарии на русском
