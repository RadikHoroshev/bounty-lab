# Bounty Lab

Security research repository focused on AI/ML bug bounty programs.

## Structure

```
bounty-lab/
├── docs/
│   ├── sessions/     — research session notes
│   └── research/     — methodology and tooling research
├── targets/
│   ├── litellm/      — findings for LiteLLM
│   ├── ollama/       — findings for Ollama
│   └── open-webui/   — findings for Open WebUI
├── tools/
│   └── scripts/      — helper scripts
├── findings/         — vulnerability reports
├── knowledge/        — vulnerability patterns
└── README.md
```

## Research Areas

- AI/ML inference servers (LiteLLM, Ollama, Open WebUI)
- Common vulnerability classes: SSRF, SSTI, path traversal, RCE
- Verification scripts for each finding
