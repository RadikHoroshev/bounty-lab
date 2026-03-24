## TEST PLAN — verify_litellm_ssti.py

### Requirements
- Install: `pip install jinja2`
- Vulnerable service: **not needed** — script tests Jinja2 environment directly
- Patched service: N/A

### Scenario A — no dependencies (jinja2 not installed)
1. Убедиться что jinja2 не установлен: `pip uninstall jinja2 -y`
2. `python3 verify_litellm_ssti.py`
3. Записать: exit code + первые 5 строк stdout

**Expected:** exit code = 1

### Scenario B — jinja2 installed (normal run)
1. Установить jinja2: `pip install jinja2`
2. `python3 verify_litellm_ssti.py`
3. Записать: exit code + весь вывод

**Expected:** exit code = 0, вывод содержит `uid=` и `[VULNERABLE]`

### Scenario C — alternative: verify no service needed
1. `python3 verify_litellm_ssti.py` (с установленным jinja2)
2. Записать: exit code + последние 10 строк stdout

**Expected:** exit code = 0

### Capture check
- Нет capture server — скрипт не использует сеть
- CAPTURE_PORT: N/A
- CAPTURE_URL: N/A
