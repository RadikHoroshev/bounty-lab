#!/usr/bin/env python3
"""
LiteLLM Security Findings — Neutral Verification Test
Runs independently, no assumptions, reports raw results only.
"""
import requests, time, sys

BASE = "http://localhost:4000"
MASTER = "sk-master-test-1234"
PASS = "🟢 PASS"
FAIL = "🔴 FAIL"
SKIP = "⚪ SKIP"

results = {}

def check(name, fn):
    try:
        result, detail = fn()
        results[name] = result
        status = PASS if result else FAIL
        print(f"  {status}  {name}")
        if detail:
            print(f"         {detail}")
    except Exception as e:
        results[name] = None
        print(f"  {SKIP}  {name} — ERROR: {e}")

print("=" * 60)
print("  LiteLLM Neutral Verification Test")
print(f"  Target: {BASE}")
print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

# ── Pre-check: server alive
print("\n[0] Server status")
check("Server is running",
    lambda: (requests.get(f"{BASE}/health/liveliness", timeout=5).status_code == 200, None))

# ── Test 1: /health/readiness without auth
print("\n[1] /health/readiness — unauthenticated access")

def test_readiness_open():
    r = requests.get(f"{BASE}/health/readiness", timeout=5)
    return r.status_code == 200, f"HTTP {r.status_code}"

def test_readiness_has_version():
    r = requests.get(f"{BASE}/health/readiness", timeout=5)
    d = r.json()
    v = d.get("litellm_version", "")
    return bool(v), f"version={v}"

def test_readiness_has_callbacks():
    r = requests.get(f"{BASE}/health/readiness", timeout=5)
    d = r.json()
    cb = d.get("success_callbacks", [])
    return len(cb) > 0, f"callbacks={cb}"

def test_health_requires_auth():
    r = requests.get(f"{BASE}/health", timeout=5)
    return r.status_code == 401, f"HTTP {r.status_code} (expected 401)"

check("readiness returns 200 without auth (run 1)", test_readiness_open)
check("readiness returns 200 without auth (run 2)", test_readiness_open)
check("readiness returns 200 without auth (run 3)", test_readiness_open)
check("readiness response contains litellm_version", test_readiness_has_version)
check("readiness response contains success_callbacks", test_readiness_has_callbacks)
check("/health (base) requires auth — proves inconsistency", test_health_requires_auth)

# ── Test 2: /debug/asyncio-tasks without auth
print("\n[2] /debug/asyncio-tasks — unauthenticated access")

def test_debug_tasks_open():
    r = requests.get(f"{BASE}/debug/asyncio-tasks", timeout=5)
    return r.status_code == 200, f"HTTP {r.status_code}"

def test_debug_memory_protected():
    r = requests.get(f"{BASE}/debug/memory/summary", timeout=5)
    return r.status_code in (401, 403), f"HTTP {r.status_code} (expected 401/403)"

check("debug/asyncio-tasks returns 200 without auth", test_debug_tasks_open)
check("debug/asyncio-tasks returns 200 (run 2)", test_debug_tasks_open)
check("debug/memory/summary IS protected (for comparison)", test_debug_memory_protected)

# ── Test 3: /routes exposes full route map without auth
print("\n[3] /routes — full API map without auth")

def test_routes_open():
    r = requests.get(f"{BASE}/routes", timeout=5)
    return r.status_code == 200, f"HTTP {r.status_code}"

def test_routes_count():
    r = requests.get(f"{BASE}/routes", timeout=5)
    n = len(r.json().get("routes", []))
    return n > 100, f"{n} routes exposed"

def test_routes_has_admin_paths():
    r = requests.get(f"{BASE}/routes", timeout=5)
    paths = [rt.get("path","") for rt in r.json().get("routes",[])]
    admin = [p for p in paths if any(k in p for k in ["/key/","/user/","/spend/","/global/"])]
    return len(admin) > 10, f"{len(admin)} admin paths visible"

check("/routes returns 200 without auth", test_routes_open)
check("/routes exposes >100 endpoints", test_routes_count)
check("/routes reveals admin/sensitive paths", test_routes_has_admin_paths)

# ── Test 4: Auth is properly enforced on sensitive endpoints
print("\n[4] Sensitive endpoints — auth enforcement (should all be protected)")

protected = [
    "/spend/logs", "/user/list", "/key/list",
    "/global/spend", "/model/info", "/key/info"
]
for ep in protected:
    path = ep
    check(f"{ep} requires auth",
        lambda p=path: (requests.get(f"{BASE}{p}", timeout=5).status_code in (401,403),
                        f"HTTP {requests.get(f'{BASE}{p}', timeout=5).status_code}"))

# ── Summary
print("\n" + "=" * 60)
confirmed = [k for k, v in results.items() if v is True]
failed    = [k for k, v in results.items() if v is False]
skipped   = [k for k, v in results.items() if v is None]

print(f"  Total:     {len(results)}")
print(f"  {PASS}:  {len(confirmed)}")
print(f"  {FAIL}:  {len(failed)}")
print(f"  {SKIP}:  {len(skipped)}")

print("\n  FINDINGS:")
# Finding 1
r1 = all(results.get(k) for k in [
    "readiness returns 200 without auth (run 1)",
    "readiness returns 200 without auth (run 2)",
    "readiness returns 200 without auth (run 3)",
    "readiness response contains litellm_version",
    "readiness response contains success_callbacks",
    "/health (base) requires auth — proves inconsistency",
])
print(f"  {'🔴 CONFIRMED' if r1 else '🟢 NOT CONFIRMED'}  Finding #1: /health/readiness info disclosure")

# Finding 2
r2 = results.get("debug/asyncio-tasks returns 200 without auth") and \
     results.get("debug/asyncio-tasks returns 200 (run 2)")
print(f"  {'🔴 CONFIRMED' if r2 else '🟢 NOT CONFIRMED'}  Finding #2: /debug/asyncio-tasks open without auth")

# Finding 3
r3 = results.get("/routes returns 200 without auth") and \
     results.get("/routes exposes >100 endpoints") and \
     results.get("/routes reveals admin/sensitive paths")
print(f"  {'🔴 CONFIRMED' if r3 else '🟢 NOT CONFIRMED'}  Finding #3: /routes full API map exposed")

print("=" * 60)
sys.exit(0 if (r1 and r2 and r3) else 1)
