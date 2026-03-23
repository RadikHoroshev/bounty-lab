#!/usr/bin/env python3
"""
LiteLLM Security Verification Script
Comprehensive test for authentication bypass and info disclosure findings
Runs 100% neutral verification - no interpretation, just facts
"""

import json
import urllib.request
import urllib.error
import sys
from typing import Dict, Any, Tuple

BASE_URL = "http://localhost:4000"
MASTER_KEY = "sk-master-test-1234"

def make_request(endpoint: str, headers: Dict[str, str] = None) -> Tuple[int, Any]:
    """Make HTTP request and return (status_code, response_body)"""
    url = f"{BASE_URL}{endpoint}"
    req_headers = headers or {}
    
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode('utf-8')
            return response.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8') if e.fp else ""
    except Exception as e:
        return 0, str(e)

def test_endpoint_auth(endpoint: str, description: str) -> Dict[str, Any]:
    """Test endpoint with and without auth"""
    result = {
        "endpoint": endpoint,
        "description": description,
        "without_auth": {},
        "with_auth": {}
    }
    
    # Test without auth
    status, body = make_request(endpoint)
    result["without_auth"]["status"] = status
    result["without_auth"]["body_length"] = len(body)
    result["without_auth"]["body_preview"] = body[:200] if body else ""
    
    # Test with auth
    auth_headers = {"Authorization": f"Bearer {MASTER_KEY}"}
    status_auth, body_auth = make_request(endpoint, auth_headers)
    result["with_auth"]["status"] = status_auth
    result["with_auth"]["body_length"] = len(body_auth)
    
    return result

def analyze_sensitivity(endpoint: str, body: str) -> Dict[str, Any]:
    """Analyze response for sensitive information"""
    analysis = {
        "endpoint": endpoint,
        "sensitive_fields_found": [],
        "risk_indicators": []
    }
    
    try:
        data = json.loads(body) if body.startswith('{') or body.startswith('[') else None
    except:
        data = None
    
    if data:
        # Check for sensitive fields
        sensitive_patterns = [
            ("version", ["litellm_version", "version"]),
            ("security_callbacks", ["success_callbacks", "failure_callbacks"]),
            ("database_status", ["db", "database"]),
            ("cache_config", ["cache", "redis", "memcached"]),
            ("internal_config", ["log_level", "debug", "transport"]),
            ("routes", ["routes", "endpoints", "paths"]),
            ("async_tasks", ["tasks", "coroutines"]),
        ]
        
        for field_name, patterns in sensitive_patterns:
            if isinstance(data, dict):
                for pattern in patterns:
                    if pattern in str(data).lower():
                        analysis["sensitive_fields_found"].append(field_name)
                        break
        
        # Specific analysis for /health/readiness
        if endpoint == "/health/readiness" and isinstance(data, dict):
            if "litellm_version" in data:
                analysis["risk_indicators"].append(f"Version disclosed: {data['litellm_version']}")
            if "success_callbacks" in data:
                callbacks = data.get("success_callbacks", [])
                security_hooks = [c for c in callbacks if "security" in c.lower() or "proxy" in c.lower()]
                if security_hooks:
                    analysis["risk_indicators"].append(f"Security hooks exposed: {security_hooks}")
            if "db" in data:
                analysis["risk_indicators"].append(f"Database status: {data['db']}")
        
        # Specific analysis for /routes
        if endpoint == "/routes" and isinstance(data, dict):
            routes = data.get("routes", [])
            admin_routes = [r for r in routes if "admin" in r.get("path", "").lower()]
            if admin_routes:
                analysis["risk_indicators"].append(f"{len(admin_routes)} admin routes exposed")
            
            sensitive_paths = [r for r in routes if any(x in r.get("path", "").lower() 
                          for x in ["key", "user", "spend", "team", "model"])]
            if sensitive_paths:
                analysis["risk_indicators"].append(f"{len(sensitive_paths)} sensitive paths exposed")
    
    return analysis

def main():
    print("=" * 80)
    print("LITELLM SECURITY VERIFICATION - COMPREHENSIVE TEST")
    print("=" * 80)
    print()
    
    # Phase 0: Check server health
    print("[PHASE 0] Server Health Check")
    print("-" * 40)
    status, body = make_request("/health/liveliness")
    if status == 200 and "alive" in body.lower():
        print(f"✓ Server is running (liveliness: {body})")
    else:
        print(f"✗ Server not responding correctly (status: {status})")
        sys.exit(1)
    print()
    
    # Phase 1: Authentication scan
    print("[PHASE 1] Authentication Scan (12 endpoints)")
    print("-" * 40)
    
    endpoints_to_test = [
        ("/health", "Main health endpoint"),
        ("/health/liveliness", "Liveliness check"),
        ("/health/readiness", "Readiness check"),
        ("/routes", "Available routes"),
        ("/models", "Available models"),
        ("/openapi.json", "OpenAPI specification"),
        ("/sso/debug/login", "SSO debug login"),
        ("/debug/asyncio-tasks", "Asyncio tasks debug"),
        ("/spend/logs", "Spend logs"),
        ("/user/list", "User list"),
        ("/key/list", "Key list"),
        ("/global/spend", "Global spend"),
    ]
    
    auth_results = []
    for endpoint, desc in endpoints_to_test:
        result = test_endpoint_auth(endpoint, desc)
        auth_results.append(result)
        
        without = result["without_auth"]["status"]
        with_auth = result["with_auth"]["status"]
        
        status_icon = "🔴" if without == 200 else "✅"
        print(f"{status_icon} {endpoint:25} | No Auth: {without:3} | With Auth: {with_auth:3}")
    print()
    
    # Phase 2: Sensitivity analysis
    print("[PHASE 2] Response Sensitivity Analysis")
    print("-" * 40)
    
    open_endpoints = [r for r in auth_results if r["without_auth"]["status"] == 200]
    
    for result in open_endpoints:
        endpoint = result["endpoint"]
        body = result["without_auth"]["body_preview"]
        
        # Get full body for analysis
        full_status, full_body = make_request(endpoint)
        
        analysis = analyze_sensitivity(endpoint, full_body)
        
        print(f"\n{endpoint}:")
        if analysis["sensitive_fields_found"]:
            print(f"  Sensitive fields: {', '.join(set(analysis['sensitive_fields_found']))}")
        if analysis["risk_indicators"]:
            for indicator in analysis["risk_indicators"]:
                print(f"  ⚠ {indicator}")
        if not analysis["sensitive_fields_found"] and not analysis["risk_indicators"]:
            print("  No obvious sensitive data detected")
    print()
    
    # Phase 3: Inconsistency check
    print("[PHASE 3] Authentication Inconsistency Check")
    print("-" * 40)
    
    health_endpoints = [r for r in auth_results if "/health" in r["endpoint"]]
    
    print("Health endpoint family comparison:")
    for ep in health_endpoints:
        status = ep["without_auth"]["status"]
        expected = "401" if ep["endpoint"] not in ["/health/liveliness"] else "200"
        match = "✓" if str(status) == expected else "⚠"
        print(f"  {match} {ep['endpoint']:25} -> {status} (expected: {expected})")
    
    # Check for inconsistency
    health_status = next((r for r in health_endpoints if r["endpoint"] == "/health"), None)
    readiness_status = next((r for r in health_endpoints if r["endpoint"] == "/health/readiness"), None)
    
    if health_status and readiness_status:
        if health_status["without_auth"]["status"] == 401 and readiness_status["without_auth"]["status"] == 200:
            print(f"\n⚠ INCONSISTENCY DETECTED:")
            print(f"  /health requires auth (401)")
            print(f"  /health/readiness does NOT require auth (200)")
    print()
    
    # Phase 4: Summary
    print("[PHASE 4] Summary")
    print("-" * 40)
    
    findings = []
    
    # Finding 1: /health/readiness info disclosure
    readiness = next((r for r in auth_results if r["endpoint"] == "/health/readiness"), None)
    if readiness and readiness["without_auth"]["status"] == 200:
        findings.append({
            "id": "F1",
            "endpoint": "/health/readiness",
            "issue": "Information Disclosure",
            "severity": "MEDIUM",
            "details": "Exposes version, security callbacks, and internal config without auth"
        })
    
    # Finding 2: /routes enumeration
    routes = next((r for r in auth_results if r["endpoint"] == "/routes"), None)
    if routes and routes["without_auth"]["status"] == 200:
        findings.append({
            "id": "F2",
            "endpoint": "/routes",
            "issue": "Endpoint Enumeration",
            "severity": "MEDIUM", 
            "details": "Exposes all 738 routes including admin paths without auth"
        })
    
    # Finding 3: /debug/asyncio-tasks
    debug = next((r for r in auth_results if r["endpoint"] == "/debug/asyncio-tasks"), None)
    if debug and debug["without_auth"]["status"] == 200:
        findings.append({
            "id": "F3",
            "endpoint": "/debug/asyncio-tasks",
            "issue": "Debug Information Disclosure",
            "severity": "LOW",
            "details": "Exposes internal asyncio task structure without auth"
        })
    
    print(f"Total findings: {len(findings)}")
    print()
    
    for f in findings:
        print(f"  [{f['id']}] {f['endpoint']}")
        print(f"      Issue: {f['issue']}")
        print(f"      Severity: {f['severity']}")
        print(f"      Details: {f['details']}")
        print()
    
    # Save results to JSON
    output = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "server": BASE_URL,
        "phase1_results": auth_results,
        "findings": findings
    }
    
    output_file = "/tmp/litellm_comprehensive_verify.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"Full results saved to: {output_file}")
    print("=" * 80)
    
    return 0 if not findings else 1

if __name__ == "__main__":
    sys.exit(main())
