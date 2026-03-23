# LibFuzzer — Coverage-Guided Fuzzing

Source: LLVM Documentation (Apache 2.0)

## What is LibFuzzer

In-process, coverage-guided, evolutionary fuzzing engine.
- Linked directly with the target library
- Tracks code coverage via SanitizerCoverage instrumentation
- Generates mutations to maximize path coverage
- Single-threaded per process (multi-process supported)

**Best for:** Parsers, regex matchers, compression, crypto, network protocol libraries — anything that takes a byte array input.

**Not suited for:** Targets that validate input via hard crashes/assertions, tests >100ms, persistent background threads, dlclose() calls.

---

## Minimal Fuzz Target

```c
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  DoSomethingInterestingWithMyAPI(Data, Size);
  return 0;   // return -1 to reject input from corpus without counting as error
}
```

**Rules:**
- Accept ANY input (empty, oversized, malformed) — never crash on bad input
- Never call `exit()` on invalid input
- Deterministic: don't use random seeds based on time
- Fast: avoid O(n³) complexity
- Minimize global state

---

## Build Commands

```bash
# Basic
clang -g -O1 -fsanitize=fuzzer mytarget.c

# With AddressSanitizer (recommended)
clang -g -O1 -fsanitize=fuzzer,address mytarget.c

# With UBSan
clang -g -O1 -fsanitize=fuzzer,undefined mytarget.c

# Instrumentation only (for custom main)
clang -fsanitize=fuzzer-no-link mytarget.c
```

---

## Running

```bash
# Basic — create corpus dir first
mkdir CORPUS_DIR
cp seed_inputs/* CORPUS_DIR/
./fuzzer CORPUS_DIR

# Parallel (30 jobs, auto CPU/2 workers)
./fuzzer -jobs=30 CORPUS_DIR

# With dictionary
./fuzzer -dict=dictionary.txt CORPUS_DIR

# Time-limited run
./fuzzer -max_total_time=3600 CORPUS_DIR

# Fork mode (crash-resistant)
./fuzzer -fork=4 CORPUS_DIR
```

---

## Key Flags

| Flag | Purpose | Recommended |
|---|---|---|
| `-runs=N` | Max iterations (-1 = infinite) | -1 for production |
| `-max_len=N` | Max input size | Match target's max |
| `-timeout=N` | Seconds per input | 10-60 |
| `-rss_limit_mb=N` | Memory limit | 2048 |
| `-dict=FILE` | Keyword dictionary | Always use if available |
| `-jobs=N` | Parallel instances | CPU count |
| `-fork=N` | Crash-resilient mode | For long runs |
| `-use_value_profile=1` | CMP-value guided | Helps find magic values |
| `-only_ascii=1` | ASCII-only inputs | Text parsers |
| `-merge=1` | Minimize corpus | After long runs |
| `-artifact_prefix=PATH` | Where to save crashes | Set explicitly |

---

## Corpus Management

```bash
# Minimize corpus (remove redundant inputs)
mkdir MINIMIZED
./fuzzer -merge=1 MINIMIZED FULL_CORPUS

# Resumable merge (large corpuses)
./fuzzer CORPUS1 CORPUS2 -merge=1 -merge_control_file=/tmp/merge_ctrl
# To stop: killall -SIGUSR1 fuzzer_binary
# Resume: same command again

# Regression test (replay known crashes)
./fuzzer crash_file1 crash_file2
```

---

## Output Events

```
READ     ← loaded corpus sample
INITED   ← initialization complete
NEW      ← found new coverage-expanding input (save this)
REDUCE   ← found smaller input with same coverage
DONE     ← reached run/time limit

# Stats fields:
cov:     block/edge coverage count
ft:      feature signals (more granular than cov)
corp:    corpus size (count/bytes)
exec/s:  iterations per second
rss:     memory usage MB
```

---

## Dictionary Format

```
# AFL-compatible format
kw1="Content-Type"
kw2="Authorization"
kw3="\x00\xff"
"<script>"
"' OR '1'='1"
```

---

## Fuzzer-Friendly Code Pattern

```c
#include <stdint.h>
#include <stddef.h>

// Make code deterministic for fuzzing:
void MyInitPRNG() {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  srand(0);   // fixed seed
#else
  srand(time(0));
#endif
}

// Reject invalid inputs early (return -1):
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (auto *Obj = ParseInput(Data, Size)) {
    Obj->DoWork();
    return 0;
  }
  return -1;  // rejected, not a crash
}
```

---

## Toy Example — Finding a Bug

```c
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'H')
    if (size > 1 && data[1] == 'I')
      if (size > 2 && data[2] == '!')
        __builtin_trap();   // simulated crash
  return 0;
}
```

```bash
clang++ -fsanitize=address,fuzzer toy.cc
./a.out   # finds "HI!" in seconds
```

---

## AFL Integration

LibFuzzer and AFL can share corpus directories (run sequentially, not simultaneously):
```bash
# AFL → LibFuzzer corpus sharing
afl-fuzz -i corpus/ -o afl_out/ ./target @@
./libfuzzer_target afl_out/queue/
```

---

## Platform Notes

- **Linux/macOS**: built with LLVM by default
- **Windows**: Clang 9+, ASAN mandatory, no `/INCREMENTAL`
- Note: Original authors moved to "Centipede" — libFuzzer gets bug fixes only

---

## Application to Bug Bounty

```
# Targets where fuzzing finds bugs:
- JSON/YAML parsers with user-supplied content
- Image/file processors (Pillow, ImageMagick)
- Template engines (Jinja2, Mako) — feed it weird templates
- Protocol parsers in AI inference servers (Ollama, vLLM)
- Binary format parsers in ML model loaders (GGUF, ONNX, safetensors)

# Typical findings:
- Heap buffer overflow in C extension
- Integer overflow in size calculation
- Use-after-free in parser
- OOM / resource exhaustion (DoS)
- Infinite loop / hang
```
