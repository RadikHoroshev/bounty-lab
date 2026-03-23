#!/opt/homebrew/bin/python3.11
"""
Create test accounts for security research in Open WebUI.
Inserts admin@local.test (Admin2024) and user@local.test (User2024)
directly into the SQLite database.
"""
import sqlite3
import uuid
import time
import sys

DB_PATH = "/opt/homebrew/lib/python3.11/site-packages/open_webui/data/webui.db"

try:
    import bcrypt
except ImportError:
    sys.exit("[!] bcrypt not found. Run: pip install bcrypt")

ACCOUNTS = [
    {"email": "admin@local.test", "password": "Admin2024", "name": "Test Admin", "role": "admin"},
    {"email": "user@local.test",  "password": "User2024",  "name": "Test User",  "role": "user"},
]

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

con = sqlite3.connect(DB_PATH)
cur = con.cursor()
now = int(time.time())

for acc in ACCOUNTS:
    email = acc["email"]

    # Check if already exists
    cur.execute("SELECT id FROM auth WHERE email = ?", (email,))
    row = cur.fetchone()

    if row:
        # Update password only
        uid = row[0]
        hashed = hash_password(acc["password"])
        cur.execute("UPDATE auth SET password = ? WHERE id = ?", (hashed, uid))
        print(f"  [updated] {email} — password reset to '{acc['password']}'")
    else:
        uid = str(uuid.uuid4())
        hashed = hash_password(acc["password"])

        cur.execute(
            "INSERT INTO auth (id, email, password, active) VALUES (?, ?, ?, 1)",
            (uid, email, hashed),
        )
        cur.execute(
            """INSERT INTO user
               (id, name, email, role, profile_image_url, created_at, updated_at, last_active_at)
               VALUES (?, ?, ?, ?, '', ?, ?, ?)""",
            (uid, acc["name"], email, acc["role"], now, now, now),
        )
        print(f"  [created] {email} (role={acc['role']}, pass='{acc['password']}')")

con.commit()
con.close()
print("\n[*] Done. Test accounts are ready.")
print("    admin@local.test / Admin2024")
print("    user@local.test  / User2024")
