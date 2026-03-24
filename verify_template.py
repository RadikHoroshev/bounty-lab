#!/usr/bin/env python3
"""
verify_<TARGET>_<TYPE>.py
-------------------------
<ONE LINE DESCRIPTION>

How it works:
  <BRIEF DESCRIPTION>

Requirements:
  - Python 3.8+
  - <DEPS>  (pip install <DEPS>)
  - <SERVICE IF NEEDED>
  - Port <CAPTURE_PORT> must be free (capture server)   ← remove if no capture

Note:
  Step 1 and 2 require <SERVICE>.
  Step 3 (<FIX DESCRIPTION>) runs without any service — tests pure Python logic.

Usage:
  python3 verify_<TARGET>_<TYPE>.py
  python3 verify_<TARGET>_<TYPE>.py --endpoint http://localhost:<PORT>/...

Exit codes:
  0 — vulnerability confirmed
  1 — dependency error or service unreachable
  2 — not reproduced (may already be patched)
"""

# ── CONFIGURE THIS BLOCK ─────────────────────────────────────────────────────
TARGET      = "<target>"          # e.g. "litellm", "ollama"
VULN_TYPE   = "<type>"            # e.g. "ssrf", "ssti", "rce"
CVSS        = "<N.N> <Severity>"  # e.g. "7.7 High"
CWE         = "<NNN>"             # e.g. "918"
AFFECTED    = "<owner/repo> ≤ <version>"
CAPTURE_PORT = 0                  # set to port number if using capture server; 0 = no capture
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import sys

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip install requests")
    sys.exit(1)

# Optional: capture server imports (uncomment if CAPTURE_PORT > 0)
# import http.server
# import queue
# import threading
# import time

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
# Banner  — CVSS must match report and huntr form
# ---------------------------------------------------------------------------
BANNER = f"""
{bold(cyan('╔══════════════════════════════════════════════════════════════╗'))}
{bold(cyan(f'║  {TARGET.upper()} {VULN_TYPE.upper()} Verifier — <SHORT DESCRIPTION>  ║'))}
{bold(cyan(f'║  CVE: TBD  |  CVSS: {CVSS}  |  CWE-{CWE}  ║'))}
{bold(cyan(f'║  Affected: {AFFECTED}  ║'))}
{bold(cyan('╚══════════════════════════════════════════════════════════════╝'))}
"""

# ---------------------------------------------------------------------------
# Capture server  (delete this section if CAPTURE_PORT == 0)
# ---------------------------------------------------------------------------
# CAPTURE_URL = f"http://127.0.0.1:{CAPTURE_PORT}/<path>"
# captured: queue.Queue = queue.Queue()
#
# class CaptureHandler(http.server.BaseHTTPRequestHandler):
#     def do_POST(self):
#         length = int(self.headers.get("Content-Length", 0))
#         body = self.rfile.read(length)
#         captured.put({"method": "POST", "path": self.path, "body": body.decode(errors="replace")})
#         self.send_response(200)
#         self.send_header("Content-Type", "application/json")
#         self.end_headers()
#         self.wfile.write(b'{"error":"captured"}')
#     def do_GET(self):
#         captured.put({"method": "GET", "path": self.path})
#         self.send_response(200)
#         self.end_headers()
#         self.wfile.write(b'captured')
#     def log_message(self, *args):
#         pass
#
# def start_capture_server():
#     server = http.server.HTTPServer(("127.0.0.1", CAPTURE_PORT), CaptureHandler)
#     t = threading.Thread(target=server.serve_forever, daemon=True)
#     t.start()
#     return t

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
def step1_sanity(endpoint: str) -> bool:
    """[STEP 1] Sanity check — target reachable. Returns False → exit(1)"""
    print(f"\n{bold('[STEP 1] Sanity check — service reachable')}")
    try:
        resp = requests.get(endpoint, timeout=3)
        print(green(f"  [+] Service accessible — HTTP {resp.status_code}"))
        return True
    except requests.exceptions.ConnectionError:
        print(red(f"  [-] Cannot reach service at {endpoint}"))
        return False
    except Exception as e:
        print(red(f"  [-] Error: {e}"))
        return False


def step2_exploit(endpoint: str) -> bool:
    """[STEP 2] Confirm vulnerability. Returns True → VULNERABLE (exit 0)"""
    print(f"\n{bold('[STEP 2] Exploit — <DESCRIPTION>')}")
    # TODO: implement exploit
    # If using capture server:
    #   drain queue → send malicious request → sleep(0.3) → check queue
    vuln_confirmed = False
    if vuln_confirmed:
        print(red(f"  [VULN] <WHAT WAS CONFIRMED>"))
    else:
        print(yellow(f"  [?] Not confirmed — <REASON>"))
    return vuln_confirmed


def step3_fix() -> bool:
    """[STEP 3] Verify proposed fix blocks the vulnerability. Standalone — no service needed."""
    print(f"\n{bold('[STEP 3] Verify fix — <FIX DESCRIPTION>')}")
    # TODO: implement fix validation
    all_blocked = True
    if all_blocked:
        print(green(f"  [+] Fix correctly blocks the vulnerability"))
    else:
        print(red(f"  [-] Fix incomplete — review output above"))
    return all_blocked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=f"Verify {TARGET} {VULN_TYPE} vulnerability")
    parser.add_argument("--endpoint", default="http://localhost:<PORT>/<PATH>",
                        help="Target endpoint URL")
    args = parser.parse_args()

    print(BANNER)

    # Uncomment if using capture server:
    # print(f"{bold('Setup:')} starting capture server on 127.0.0.1:{CAPTURE_PORT} ...")
    # start_capture_server()
    # time.sleep(0.2)
    # print(green("  [+] Capture server ready"))

    try:
        if not step1_sanity(args.endpoint):
            sys.exit(1)

        vuln_confirmed = step2_exploit(args.endpoint)
        fix_works = step3_fix()

        print(f"\n{bold('='*64)}")
        if vuln_confirmed:
            print(red(bold(f"  RESULT: VULNERABLE — <IMPACT SUMMARY>")))
        else:
            print(yellow(bold("  RESULT: Could not confirm — check service logs")))

        if fix_works:
            print(green(bold("  FIX:    Proposed fix correctly blocks the vulnerability")))
        else:
            print(red(bold("  FIX:    Fix has gaps — review step 3 output")))
        print(f"{bold('='*64)}\n")

        sys.exit(0 if vuln_confirmed else 2)

    except KeyboardInterrupt:
        print(yellow("\n[!] Interrupted by user"))
        sys.exit(1)


if __name__ == "__main__":
    main()
