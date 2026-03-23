#!/usr/bin/env python3
"""
Open WebUI API Reconnaissance
Цель: найти незащищённые endpoints, IDOR, information disclosure
"""
import requests
import json

BASE = "http://localhost:3000"
session = requests.Session()

print("=" * 60)
print("  Open WebUI API Recon")
print("=" * 60)

# 1. Логин — получаем токен
print("\n[*] Аутентификация...")
r = session.post(f"{BASE}/api/v1/auths/signin", json={
    "email": "admin@local.test",
    "password": "Admin2024"
})
if r.status_code == 200:
    token = r.json().get("token")
    session.headers["Authorization"] = f"Bearer {token}"
    print(f"  [OK] Token получен")
else:
    print(f"  [!] Ошибка: {r.status_code} {r.text[:100]}")
    exit(1)

# 2. Перебор endpoints без аутентификации
print("\n[*] Проверка endpoints без токена...")
unauth = requests.Session()
endpoints = [
    ("GET", "/api/v1/auths/"),
    ("GET", "/api/v1/users/"),
    ("GET", "/api/v1/users/all"),
    ("GET", "/api/v1/chats/"),
    ("GET", "/api/v1/chats/all"),
    ("GET", "/api/v1/files/"),
    ("GET", "/api/v1/knowledge/"),
    ("GET", "/api/v1/models/"),
    ("GET", "/api/config"),
    ("GET", "/api/config/models"),
    ("GET", "/api/version"),
    ("GET", "/health"),
    ("GET", "/api/v1/tools/"),
    ("GET", "/api/v1/functions/"),
    ("GET", "/api/v1/groups/"),
    ("GET", "/api/v1/notes/"),
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/redoc"),
]

for method, path in endpoints:
    try:
        r = unauth.request(method, f"{BASE}{path}", timeout=3)
        icon = "🟡" if r.status_code == 200 else "🟢" if r.status_code in [401, 403] else "🔵"
        print(f"  {icon} {method} {path} → {r.status_code}")
        if r.status_code == 200:
            try:
                data = r.json()
                print(f"       {str(data)[:100]}")
            except:
                print(f"       {r.text[:100]}")
    except Exception as e:
        print(f"  [ERR] {path}: {e}")

# 3. Проверка с токеном — что доступно admin
print("\n[*] Endpoints с admin токеном...")
auth_endpoints = [
    ("GET", "/api/v1/users/all"),
    ("GET", "/api/v1/users/permissions"),
    ("GET", "/api/v1/auths/admin/details"),
    ("GET", "/api/v1/auths/admin/config"),
    ("GET", "/api/config/export"),
    ("GET", "/api/v1/secrets/"),
]
for method, path in auth_endpoints:
    try:
        r = session.request(method, f"{BASE}{path}", timeout=3)
        print(f"  [{r.status_code}] {method} {path}")
        if r.status_code == 200:
            try:
                data = r.json()
                print(f"       {str(data)[:150]}")
            except:
                print(f"       {r.text[:150]}")
    except Exception as e:
        print(f"  [ERR] {path}: {e}")

print("\n[*] Готово.")
