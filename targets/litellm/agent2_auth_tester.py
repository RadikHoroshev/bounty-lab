#!/usr/bin/env python3
"""
AGENT 2 — LiteLLM Auth & Privilege Escalation Testing
Target: litellm proxy v1.82.6
Depends on: /tmp/litellm_recon.json from Agent 1
"""
import requests
import json
import time

BASE = "http://localhost:4000"
MASTER_KEY = "sk-master-test-1234"
master_headers = {"Authorization": f"Bearer {MASTER_KEY}"}

print("=" * 60)
print("  AGENT 2 — LiteLLM Auth & Privilege Testing")
print("=" * 60)

# ── Step 1: Create a regular (non-admin) user key
print("\n[1] Creating regular user key via master key...")
resp = requests.post(f"{BASE}/key/generate",
    headers=master_headers,
    json={"models": ["ollama/llama3.2"], "duration": "1h", "metadata": {"role": "user"}},
    timeout=5)
print(f"  POST /key/generate → {resp.status_code}")
user_key = None
if resp.status_code == 200:
    user_key = resp.json().get("key")
    print(f"  🔑 User key: {user_key[:20]}...")
else:
    print(f"  Response: {resp.text[:100]}")

user_headers = {"Authorization": f"Bearer {user_key}"} if user_key else {}

# ── Step 2: Test privileged endpoints with regular user key
print("\n[2] Testing admin endpoints with regular user key...")

privileged_endpoints = [
    ("GET",  "/key/list",            "List all API keys"),
    ("GET",  "/user/list",           "List all users"),
    ("GET",  "/spend/logs",          "View ALL spend logs"),
    ("GET",  "/spend/keys",          "View all keys spending"),
    ("GET",  "/spend/users",         "View all users spending"),
    ("GET",  "/global/spend",        "Global spend totals"),
    ("GET",  "/global/spend/logs",   "Global spend logs"),
    ("GET",  "/get/config",          "Get server config"),
    ("GET",  "/model/info",          "Get model config"),
    ("POST", "/user/new",            "Create new user"),
    ("POST", "/key/delete",          "Delete any key"),
]

findings = []
for method, path, desc in privileged_endpoints:
    try:
        r = requests.request(method, f"{BASE}{path}",
            headers=user_headers,
            json={"key": MASTER_KEY} if method == "POST" else None,
            timeout=5)
        if r.status_code == 200:
            emoji = "🔴 VULN"
            findings.append((method, path, desc, r.text[:100]))
        elif r.status_code in (401, 403):
            emoji = "🟢 BLOCKED"
        else:
            emoji = f"🟡 {r.status_code}"
        print(f"  {emoji:12} {method:4} {path:28} — {desc}")
        if r.status_code == 200:
            print(f"           Response: {r.text[:80]}")
    except Exception as e:
        print(f"  ⚪ ERR     {method:4} {path:28} — {e}")

# ── Step 3: Test unauthenticated access to all endpoints
print("\n[3] Testing without any auth token...")

sensitive_noauth = [
    ("GET", "/models",        "Model list"),
    ("GET", "/spend/logs",    "Spend logs"),
    ("GET", "/key/list",      "Key list"),
    ("GET", "/user/list",     "User list"),
    ("GET", "/get/config",    "Config"),
    ("GET", "/global/spend",  "Global spend"),
    ("GET", "/model/info",    "Model info"),
    ("GET", "/routes",        "All routes"),
    ("GET", "/openapi.json",  "API spec"),
]

noauth_findings = []
for method, path, desc in sensitive_noauth:
    try:
        r = requests.request(method, f"{BASE}{path}", timeout=5)
        if r.status_code == 200:
            emoji = "🔴 OPEN"
            noauth_findings.append((method, path, desc, r.text[:100]))
        else:
            emoji = f"🟢 {r.status_code}"
        print(f"  {emoji:12} {method:4} {path:28} — {desc}")
    except Exception as e:
        print(f"  ⚪ {e}")

# ── Step 4: Test master key exposure via /config
print("\n[4] Checking for sensitive data exposure in config endpoints...")
config_endpoints = ["/get/config", "/config/yaml", "/debug/info"]
for path in config_endpoints:
    try:
        r = requests.get(f"{BASE}{path}", headers=master_headers, timeout=5)
        if r.status_code == 200:
            body = r.text
            sensitive = []
            for kw in ["password", "secret", "api_key", "token", "sk-", "OPENAI", "ANTHROPIC"]:
                if kw.lower() in body.lower():
                    sensitive.append(kw)
            if sensitive:
                print(f"  🔴 {path} → contains: {sensitive}")
            else:
                print(f"  🟡 {path} → 200 but no obvious secrets")
    except:
        pass

# ── Summary
print("\n" + "=" * 60)
print("  FINDINGS SUMMARY")
print("=" * 60)
if findings:
    print(f"\n🔴 Privilege Escalation ({len(findings)} findings):")
    for m, p, d, body in findings:
        print(f"   {m} {p} — {d}")
if noauth_findings:
    print(f"\n🔴 Unauthenticated Access ({len(noauth_findings)} findings):")
    for m, p, d, body in noauth_findings:
        print(f"   {m} {p} — {d}")
if not findings and not noauth_findings:
    print("\n🟢 No obvious auth bypass found. Try deeper fuzzing.")

# Save results
with open("/tmp/litellm_auth_results.json", "w") as f:
    json.dump({"privilege_escalation": findings, "noauth": noauth_findings}, f, indent=2)
print("\n✅ Results saved to /tmp/litellm_auth_results.json")
