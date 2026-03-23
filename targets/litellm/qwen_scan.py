#!/usr/bin/env python3
"""
QWEN Security Scan — OpenAPI Hidden Params + Path Traversal + Rate Limiting + CORS
Target: LiteLLM v1.82.6 @ http://localhost:4000
"""

import json
import urllib.request
import urllib.error
import sys
from typing import Dict, List, Any

BASE_URL = "http://localhost:4000"

def make_request(endpoint, method="GET", headers=None, data=None, timeout=10, return_headers=False):
    """Make HTTP request and return (status_code, response_body, response_headers)"""
    url = f"{BASE_URL}{endpoint}"
    req_headers = headers or {}
    
    if data:
        data = json.dumps(data).encode('utf-8')
        req_headers["Content-Type"] = "application/json"
    
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode('utf-8')
            resp_headers = dict(response.headers)
            return (response.status, body, resp_headers) if return_headers else (response.status, body)
    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if hasattr(e, 'headers') else {}
        return (e.code, e.read().decode('utf-8') if e.fp else "", resp_headers) if return_headers else (e.code, "")
    except Exception as e:
        return (0, str(e), {}) if return_headers else (0, str(e))

def print_header(text):
    print(f"\n{'='*70}")
    print(f" {text}")
    print(f"{'='*70}")

def print_subheader(text):
    print(f"\n--- {text} ---")

print_header("QWEN SECURITY SCAN — OpenAPI + Path Traversal + Rate Limit + CORS")
print("Target: LiteLLM v1.82.6 @ http://localhost:4000")
print("Date: 2026-03-22")

# ============= PHASE 1: OpenAPI Hidden Parameters =============
print_header("PHASE 1: OpenAPI Hidden Parameters Analysis")

print_subheader("Fetching OpenAPI spec")
status, openapi_body = make_request("/openapi.json")
print(f"GET /openapi.json → {status}")

if status != 200:
    print("⚠ Cannot fetch OpenAPI spec")
    openapi_data = {}
    openapi_paths = {}
else:
    openapi_data = json.loads(openapi_body)
    openapi_paths = openapi_data.get("paths", {})
    print(f"Total paths in OpenAPI: {len(openapi_paths)}")

# Analyze parameters for sensitive/hidden fields
print_subheader("Analyzing endpoint parameters for hidden/sensitive fields")

sensitive_param_patterns = [
    ("api_key", "API key parameter"),
    ("api_base", "Custom API base URL"),
    ("base_url", "Base URL override"),
    ("secret", "Secret field"),
    ("token", "Token field"),
    ("password", "Password field"),
    ("credential", "Credential field"),
    ("private", "Private field"),
    ("internal", "Internal field"),
    ("admin", "Admin field"),
    ("debug", "Debug parameter"),
    ("verbose", "Verbose mode"),
    ("include", "Include extra data"),
    ("expand", "Expand response"),
]

findings_phase1 = []
for path, methods in list(openapi_paths.items())[:100]:  # Limit to first 100 paths
    if not isinstance(methods, dict):
        continue
    for method, details in methods.items():
        if method.lower() not in ["get", "post", "put", "delete", "patch"]:
            continue
        if not isinstance(details, dict):
            continue
        
        params = details.get("parameters", [])
        request_body = details.get("requestBody", {})
        
        # Check path/query parameters
        for param in params:
            if not isinstance(param, dict):
                continue
            param_name = param.get("name", "").lower()
            for pattern, description in sensitive_param_patterns:
                if pattern in param_name:
                    findings_phase1.append({
                        "endpoint": f"{method.upper()} {path}",
                        "param": param_name,
                        "type": param.get("in", "unknown"),
                        "description": description
                    })
        
        # Check request body schema
        if request_body and isinstance(request_body, dict):
            content = request_body.get("content", {})
            for media_type, media_details in content.items():
                if not isinstance(media_details, dict):
                    continue
                schema = media_details.get("schema", {})
                if isinstance(schema, dict):
                    properties = schema.get("properties", {})
                    for prop_name in properties.keys():
                        for pattern, description in sensitive_param_patterns:
                            if pattern in prop_name.lower():
                                findings_phase1.append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "param": prop_name,
                                    "type": "body",
                                    "description": description
                                })

print(f"Found {len(findings_phase1)} potentially sensitive parameters:")
for f in findings_phase1[:20]:
    print(f"  • {f['endpoint']} — {f['param']} ({f['type']}): {f['description']}")
if len(findings_phase1) > 20:
    print(f"  ... and {len(findings_phase1) - 20} more")

# ============= PHASE 2: Path Traversal =============
print_header("PHASE 2: Path Traversal Testing")

print_subheader("Testing path traversal on public endpoints")

traversal_payloads = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%252e%252e%252f",
    "....//",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32",
    "C:/Windows/System32",
]

public_endpoints = [
    "/health/readiness",
    "/health/liveliness",
    "/routes",
    "/openapi.json",
    "/debug/asyncio-tasks",
]

findings_phase2 = []
for endpoint in public_endpoints:
    for payload in traversal_payloads:
        test_url = f"{endpoint}?config={payload}"
        status, body = make_request(test_url, timeout=5)
        
        # Check for path traversal indicators
        if status == 200 and body:
            if "root:" in body or "bin/bash" in body or "daemon:" in body:
                findings_phase2.append({
                    "endpoint": test_url,
                    "payload": payload,
                    "status": status,
                    "severity": "CRITICAL",
                    "finding": "Possible /etc/passwd disclosure"
                })
        
        # Check for error messages that reveal paths
        if status in [400, 500] and body:
            if "/opt/" in body or "/home/" in body or "C:\\" in body.lower():
                findings_phase2.append({
                    "endpoint": test_url,
                    "payload": payload,
                    "status": status,
                    "severity": "LOW",
                    "finding": "Path disclosure in error message"
                })

print(f"Tested {len(public_endpoints) * len(traversal_payloads)} path traversal combinations")
if findings_phase2:
    print(f"⚠ Found {len(findings_phase2)} potential path traversal issues:")
    for f in findings_phase2:
        print(f"  [{f['severity']}] {f['endpoint']} — {f['finding']}")
else:
    print("✓ No path traversal vulnerabilities detected")

# Also test header-based path traversal
print_subheader("Testing header-based path traversal")

header_tests = [
    {"X-Forwarded-Host": "../config"},
    {"X-Original-URL": "../admin"},
    {"X-Rewrite-URL": "../etc/passwd"},
    {"X-Forwarded-Prefix": "/.."},
]

for headers in header_tests:
    status, body = make_request("/health/readiness", headers=headers, timeout=5)
    if status == 200 and body and ("root:" in body or "passwd" in body):
        findings_phase2.append({
            "type": "header_traversal",
            "headers": headers,
            "severity": "CRITICAL",
            "finding": "Header-based path traversal successful"
        })

print(f"Header traversal tests: {len(header_tests)} completed")

# ============= PHASE 3: Rate Limiting =============
print_header("PHASE 3: Rate Limiting Verification")

print_subheader("Testing rate limiting on public endpoints")

# Test rapid requests to public endpoints
rate_limit_endpoints = [
    "/health/readiness",
    "/health/liveliness",
    "/routes",
    "/openapi.json",
]

findings_phase3 = []
for endpoint in rate_limit_endpoints:
    print(f"\nTesting {endpoint}...")
    
    status_codes = []
    response_times = []
    
    for i in range(50):  # 50 rapid requests
        import time
        start = time.time()
        status, body = make_request(endpoint, timeout=5)
        elapsed = time.time() - start
        
        status_codes.append(status)
        response_times.append(elapsed)
    
    # Analyze results
    unique_statuses = set(status_codes)
    avg_response_time = sum(response_times) / len(response_times)
    max_response_time = max(response_times)
    
    # Check for rate limiting indicators
    if 429 in status_codes:
        findings_phase3.append({
            "endpoint": endpoint,
            "finding": "Rate limiting detected (429 returned)",
            "requests_before_limit": status_codes.index(429) + 1,
            "severity": "INFO"
        })
        print(f"  ⚠ Rate limiting detected after {status_codes.index(429) + 1} requests")
    elif 503 in status_codes:
        findings_phase3.append({
            "endpoint": endpoint,
            "finding": "Service unavailable under load (503)",
            "severity": "MEDIUM"
        })
        print(f"  ⚠ Service degradation detected")
    elif avg_response_time > 2.0:
        findings_phase3.append({
            "endpoint": endpoint,
            "finding": f"Slow response under load (avg {avg_response_time:.2f}s)",
            "severity": "LOW"
        })
        print(f"  ⚠ Slow response: avg {avg_response_time:.2f}s")
    else:
        print(f"  ✓ No rate limiting detected (all {status_codes[0]})")

# Test rate limiting with different IPs (X-Forwarded-For bypass)
print_subheader("Testing X-Forwarded-For rate limit bypass")

bypass_attempts = []
for i in range(20):
    headers = {"X-Forwarded-For": f"10.0.0.{i}"}
    status, body = make_request("/health/readiness", headers=headers, timeout=5)
    bypass_attempts.append(status)

if 429 not in bypass_attempts and 429 in status_codes:
    findings_phase3.append({
        "finding": "X-Forwarded-For bypasses rate limiting",
        "severity": "MEDIUM"
    })
    print("  ⚠ X-Forwarded-For may bypass rate limiting")
else:
    print("  ✓ X-Forwarded-For does not bypass rate limiting")

# ============= PHASE 4: Full CORS Scan =============
print_header("PHASE 4: Full CORS Scan")

print_subheader("Testing CORS configuration on all public endpoints")

cors_endpoints = [
    "/health/readiness",
    "/health/liveliness",
    "/routes",
    "/openapi.json",
    "/debug/asyncio-tasks",
    "/sso/debug/login",
]

cors_origins = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://localhost",
    "https://127.0.0.1",
]

findings_phase4 = []
cors_results = {}

for endpoint in cors_endpoints:
    cors_results[endpoint] = {}
    
    for origin in cors_origins:
        headers = {"Origin": origin}
        status, body, resp_headers = make_request(endpoint, headers=headers, timeout=5, return_headers=True)
        
        # Check CORS headers
        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        acac = resp_headers.get("Access-Control-Allow-Credentials", "")
        acah = resp_headers.get("Access-Control-Allow-Headers", "")
        
        cors_results[endpoint][origin] = {
            "acao": acao,
            "acac": acac,
            "acah": acah
        }
        
        # Check for misconfigurations
        if acao == "*" and acac == "true":
            findings_phase4.append({
                "endpoint": endpoint,
                "origin": origin,
                "finding": "CORS misconfiguration: * with credentials",
                "severity": "HIGH"
            })
        elif acao == origin or acao == "null":
            if acac == "true":
                findings_phase4.append({
                    "endpoint": endpoint,
                    "origin": origin,
                    "finding": f"Reflected Origin with credentials",
                    "severity": "MEDIUM"
                })
        elif acao == "*":
            findings_phase4.append({
                "endpoint": endpoint,
                "origin": origin,
                "finding": "Wildcard CORS (no credentials)",
                "severity": "INFO"
            })

print("CORS Test Results:")
for endpoint, results in cors_results.items():
    print(f"\n  {endpoint}:")
    for origin, headers in results.items():
        if headers["acao"]:
            print(f"    {origin}: ACAO={headers['acao']}, ACAC={headers['acac']}")

if findings_phase4:
    print(f"\n⚠ Found {len(findings_phase4)} CORS issues:")
    for f in findings_phase4:
        print(f"  [{f['severity']}] {f['endpoint']} — {f['finding']}")
else:
    print("\n✓ No critical CORS misconfigurations detected")

# Test preflight requests
print_subheader("Testing CORS preflight (OPTIONS)")

for endpoint in cors_endpoints[:3]:
    status, body, resp_headers = make_request(
        endpoint,
        method="OPTIONS",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        },
        timeout=5,
        return_headers=True
    )
    
    print(f"OPTIONS {endpoint} → {status}")
    if status == 200:
        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        acam = resp_headers.get("Access-Control-Allow-Methods", "")
        print(f"  ACAO: {acao}, ACAM: {acam}")

# ============= SUMMARY =============
print_header("SUMMARY")

print(f"\nPHASE 1 (OpenAPI Hidden Params): {len(findings_phase1)} findings")
for f in findings_phase1[:5]:
    print(f"  • {f['endpoint']} — {f['param']}")

print(f"\nPHASE 2 (Path Traversal): {len(findings_phase2)} findings")
if findings_phase2:
    for f in findings_phase2[:5]:
        print(f"  [{f['severity']}] {f['finding']}")
else:
    print("  ✓ No vulnerabilities")

print(f"\nPHASE 3 (Rate Limiting): {len(findings_phase3)} findings")
for f in findings_phase3:
    print(f"  [{f['severity']}] {f['finding']}")

print(f"\nPHASE 4 (CORS): {len(findings_phase4)} findings")
for f in findings_phase4[:5]:
    print(f"  [{f['severity']}] {f['finding']}")

# ============= FINAL VERDICT =============
print_header("FINAL VERDICT")

total_findings = len(findings_phase1) + len(findings_phase2) + len(findings_phase3) + len(findings_phase4)
critical_findings = len([f for f in findings_phase2 + findings_phase4 if f.get("severity") == "CRITICAL"])
high_findings = len([f for f in findings_phase2 + findings_phase4 if f.get("severity") == "HIGH"])

print(f"Total findings: {total_findings}")
print(f"Critical: {critical_findings}")
print(f"High: {high_findings}")

if critical_findings > 0:
    print("\n🔴 CRITICAL vulnerabilities found — immediate action required")
elif high_findings > 0:
    print("\n🟠 HIGH severity vulnerabilities found")
elif total_findings > 0:
    print("\n🟡 Informational findings — review recommended")
else:
    print("\n🟢 No significant vulnerabilities detected")

# Save results
output = {
    "phase1_openapi_params": findings_phase1,
    "phase2_path_traversal": findings_phase2,
    "phase3_rate_limiting": findings_phase3,
    "phase4_cors": findings_phase4,
    "summary": {
        "total": total_findings,
        "critical": critical_findings,
        "high": high_findings
    }
}

with open("/tmp/qwenscan_results.json", "w") as f:
    json.dump(output, f, indent=2)

print("\nResults saved to: /tmp/qwenscan_results.json")
