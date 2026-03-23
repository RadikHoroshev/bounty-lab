"""
mitmproxy addon for bug bounty research on AI/ML targets.

Usage:
  mitmdump -s mitm-intercept.py --listen-port 8080 --ssl-insecure
  mitmproxy -s mitm-intercept.py --listen-port 8080 --ssl-insecure

Then configure browser/tool proxy to 127.0.0.1:8080
"""
import json
import logging
from datetime import datetime
from pathlib import Path

from mitmproxy import http

logger = logging.getLogger(__name__)

# Patterns that may indicate interesting behaviour
INTERESTING_REQUEST_PATTERNS = [
    "eval", "exec", "__import__", "__class__", "__globals__",
    "pickle", "deserializ", "marshal",
    "template", "render", "jinja",
    "subprocess", "popen", "os.system",
    "file://", "gopher://", "dict://",
    "127.0.0.1", "169.254.169.254",  # SSRF to metadata
    "localhost",
]

INTERESTING_RESPONSE_PATTERNS = [
    "traceback", "exception", "error at line",
    "stacktrace", "django.core", "flask.app",
    "syntax error", "undefined variable",
]

LOG_DIR = Path.home() / "projects/bounty-lab/findings/traffic"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class BountyInterceptor:
    def __init__(self):
        self.req_count = 0
        self.hits = []

    def request(self, flow: http.HTTPFlow):
        self.req_count += 1
        body = flow.request.get_text(strict=False) or ""
        url = flow.request.pretty_url

        for pattern in INTERESTING_REQUEST_PATTERNS:
            if pattern.lower() in body.lower() or pattern.lower() in url.lower():
                hit = f"[REQ][{pattern}] {flow.request.method} {url}"
                logger.warning(hit)
                self.hits.append(hit)
                self._save_hit("request", pattern, flow.request.method, url, body[:500])
                break

    def response(self, flow: http.HTTPFlow):
        body = flow.response.get_text(strict=False) or ""
        url = flow.request.pretty_url
        status = flow.response.status_code

        # Flag 5xx errors
        if status >= 500:
            hit = f"[RESP][5xx:{status}] {url}"
            logger.warning(hit)
            self._save_hit("response_5xx", str(status), flow.request.method, url, body[:800])

        # Flag exception/traceback leaks
        for pattern in INTERESTING_RESPONSE_PATTERNS:
            if pattern.lower() in body.lower():
                hit = f"[RESP][{pattern}] {url}: {body[:150]}"
                logger.warning(hit)
                self._save_hit("response_leak", pattern, flow.request.method, url, body[:800])
                break

    def _save_hit(self, hit_type, pattern, method, url, body):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        fname = LOG_DIR / f"{ts}_{hit_type}_{pattern[:20]}.txt"
        try:
            fname.write_text(
                f"Type: {hit_type}\nPattern: {pattern}\n"
                f"Method: {method}\nURL: {url}\n\n"
                f"Body:\n{body}\n"
            )
        except Exception:
            pass

    def done(self):
        logger.info(f"Session complete. Requests: {self.req_count}, Hits: {len(self.hits)}")


addons = [BountyInterceptor()]
