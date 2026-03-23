#!/bin/bash
# Запускай в Warp — создаёт жертву и запускает все тесты

BASE="${OWUI_BASE:-http://localhost:3000}"
ADMIN_EMAIL="rodion@local.test"
ADMIN_PASS="Rodion2024"

echo "=== Получаем admin token ==="
TOKEN=$(curl -s -X POST "$BASE/api/v1/auths/signin" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")

if [ -z "$TOKEN" ]; then
    echo "[!] Авторизация не удалась — проверь что Open WebUI запущен на порту 3000"
    exit 1
fi
echo "  [OK] Token получен"

echo ""
echo "=== Создаём пользователя-жертву ==="
curl -s -X POST "$BASE/api/v1/auths/add" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Victim User","email":"user@local.test","password":"User2024","role":"user"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('  Email:', d.get('email','уже существует или ошибка'))" 2>/dev/null

echo ""
echo "=== Запускаем advanced_tester.py ==="
cd "$(dirname "$0")"
export OWUI_ADMIN_EMAIL="$ADMIN_EMAIL"
export OWUI_ADMIN_PASS="$ADMIN_PASS"
export OWUI_USER_EMAIL="user@local.test"
export OWUI_USER_PASS="User2024"
python3 advanced_tester.py 2>&1
