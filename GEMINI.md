# Bounty Lab — Project Rules for Jules

## ⚠️ PROTECTED FILES — DO NOT MODIFY OR DELETE

The following files and directories contain active vulnerability submissions
on Huntr. Their filenames, paths, and content must NOT be changed:

```
findings/                         ← active Huntr submission reports
findings/SUBMISSION_STATUS.md     ← current submission tracker
findings/litellm-ssti-rce.md
findings/litellm-ssti-rce-full-report.md
findings/litellm-api-base-ssrf.md
findings/nltk-url-ssrf-file-read.md
findings/ollama-web-fetch-ssrf.md
findings/verify_litellm_ssrf.py
findings/verify_litellm_ssti.py
findings/verify_ollama_ssrf.py
targets/litellm/
targets/ollama/
targets/open-webui/
```

> Any change to these files may break Huntr submission links or invalidate
> proof-of-concept references. When in doubt — leave them untouched.

---

## Allowed Work Areas

Jules may freely create and modify files in:

```
tools/scripts/       ← helper automation
knowledge/           ← vulnerability pattern notes
docs/research/       ← methodology notes
docs/sessions/       ← new session notes
```

---

## Tasks Jules May Perform

- Add new vulnerability findings as **new files** in `findings/`
- Update `findings/SUBMISSION_STATUS.md` with new status entries
- Add new targets under `targets/` as new subdirectories
- Update `knowledge/` with new patterns
- Write and run verification scripts

---

## Tasks Jules Must NOT Perform

- Rename, move, or delete anything in `findings/` or `targets/`
- Modify existing report files after they have been submitted
- Add tracking files, config files, or tooling docs at the repository root
- Commit credentials, API keys, or personal data
- Reference internal tooling, agent names, or workflow details in any file

---

## Repository Purpose

Independent security research for AI/ML bug bounty programs (Huntr).
All findings follow the BOUNTY_STANDARD.md quality standard.
