# Bug Bounty Knowledge Base

Internal tactical library for security research agents and researchers.
Organized for fast retrieval by vulnerability type — not prose, but patterns.

## Structure

```
knowledge/
├── vulns/
│   ├── xss.md            Cross-Site Scripting — all variants + bypasses
│   ├── ssti.md           Server-Side Template Injection → RCE
│   ├── ssrf.md           Server-Side Request Forgery
│   ├── sqli.md           SQL Injection
│   ├── idor.md           Insecure Direct Object Reference
│   ├── csrf.md           CSRF + XSSI
│   ├── path-traversal.md Path Traversal / LFI
│   ├── rce.md            Remote Code Execution chains
│   ├── auth-bypass.md    Auth / 2FA / OAuth bypass
│   └── misc.md           CORS, Race Conditions, Subdomain Takeover, DoS
├── tools/
│   ├── fuzzing.md        LibFuzzer complete guide
│   └── recon.md          Recon methodology
├── ai-ml-targets.md      AI/ML-specific attack surface (huntr focus)
└── writeups-index.md     Curated writeup links by vulnerability type
```

## How to Use (for agents)

1. Load the relevant `vulns/<type>.md` for the target vulnerability class
2. Check `ai-ml-targets.md` for AI/ML-specific vectors
3. Use `writeups-index.md` to find real-world examples of similar bugs
4. Use `tools/fuzzing.md` when input parsing is involved

## Sources

- Google Gruyere Web Security Codelab (CC BY-ND 3.0)
- LLVM LibFuzzer Documentation (Apache 2.0)
- Awesome-Bugbounty-Writeups (github.com/devanshbatham)
- pentester.land/writeups catalog
