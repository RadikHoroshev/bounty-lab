#!/usr/bin/env python3
"""
AGENT 1 — LiteLLM Recon & Endpoint Enumeration
Target: litellm proxy v1.82.6
Task: Map all endpoints, check which ones need auth
"""
import requests
import json

BASE = "http://localhost:4000"
MASTER_KEY = "sk-master-test-1234"
RESULTS = {}

endpoints = [
    # Health & status
    ("GET", "/health"),
    ("GET", "/health/readiness"),
    ("GET", "/health/liveliness"),
    ("GET", "/"),
    # Model info
    ("GET", "/models"),
    ("GET", "/v1/models"),
    ("GET", "/model/info"),
    ("GET", "/model/metrics"),
    # Keys
    ("GET", "/key/info"),
    ("GET", "/key/list"),
    ("POST", "/key/generate"),
    # Users
    ("GET", "/user/info"),
    ("GET", "/user/list"),
    ("POST", "/user/new"),
    # Spend / billing
    ("GET", "/spend/logs"),
    ("GET", "/spend/keys"),
    ("GET", "/spend/users"),
    ("GET", "/spend/tags"),
    # Config
    ("GET", "/get/config"),
    ("GET", "/config/yaml"),
    # Admin
    ("GET", "/global/spend"),
    ("GET", "/global/spend/logs"),
    ("GET", "/global/spend/keys"),
    ("GET", "/global/spend/models"),
    # OpenAI proxy
    ("GET", "/v1/chat/completions"),
    ("GET", "/openai/deployments"),
    # Debug
    ("GET", "/debug/info"),
    ("GET", "/routes"),
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
]

print("=" * 60)
print("  AGENT 1 — LiteLLM Endpoint Recon")
print("=" * 60)

open_endpoints = []
auth_required = []
errors = []

for method, path in endpoints:
    try:
        url = f"{BASE}{path}"
        resp = requests.request(method, url, timeout=5,
                               json={} if method == "POST" else None)
        status = resp.status_code

        if status == 200:
            emoji = "🔴"
            open_endpoints.append((method, path, status))
            try:
                body = resp.json()
                preview = str(body)[:80]
            except:
                preview = resp.text[:80]
        elif status in (401, 403):
            emoji = "🟢"
            auth_required.append((method, path, status))
            preview = resp.text[:40]
        else:
            emoji = "🟡"
            errors.append((method, path, status))
            preview = resp.text[:40]

        print(f"  {emoji} {method:4} {path:35} → {status}  {preview}")
        RESULTS[f"{method} {path}"] = {"status": status, "body": resp.text[:200]}

    except Exception as e:
        print(f"  ⚪ {method:4} {path:35} → ERR: {e}")

print("\n" + "=" * 60)
print(f"  🔴 OPEN (no auth): {len(open_endpoints)}")
for m, p, s in open_endpoints:
    print(f"     {m} {p}")

print(f"\n  🟢 Protected: {len(auth_required)}")
print(f"  🟡 Other: {len(errors)}")

# Save for Agent 2
with open("/tmp/litellm_recon.json", "w") as f:
    json.dump({"open": open_endpoints, "auth": auth_required, "raw": RESULTS}, f, indent=2)

print("\n✅ Results saved to /tmp/litellm_recon.json")
