#!/bin/bash
# Мониторинг Ollama + запуск тестов одновременно

LOG_FILE="/tmp/ollama_debug.log"
TOOLKIT_DIR="$(dirname "$0")"

echo "[*] Останавливаю Ollama service..."
brew services stop ollama 2>/dev/null
sleep 2

echo "[*] Запускаю Ollama с debug-логами в $LOG_FILE..."
OLLAMA_DEBUG=1 ollama serve > "$LOG_FILE" 2>&1 &
OLLAMA_PID=$!
echo "[*] Ollama PID: $OLLAMA_PID"

# Ждём готовности
echo "[*] Жду запуска..."
for i in {1..10}; do
    if curl -s http://localhost:11434 > /dev/null 2>&1; then
        echo "[OK] Ollama готова"
        break
    fi
    sleep 1
done

# Следим за логом в фоне, выделяем важное
tail -f "$LOG_FILE" | grep --line-buffered -E \
    "panic|segfault|segmentation|fatal|crash|ERROR|error|WARN|level=error|level=warn" \
    --color=always &
TAIL_PID=$!

echo ""
echo "[*] === Запускаю GGUF тесты ==="
echo ""

# Прогоняем тесты с захватом вывода
RESULTS=()
cd "$TOOLKIT_DIR/fuzz_gguf_output"

for modelfile in t*.Modelfile; do
    name="${modelfile%.Modelfile}"
    model_name="fuzz-${name}"
    
    echo -n "[TEST] $name ... "
    
    # Засекаем время + проверяем жив ли ollama
    START=$(python3 -c 'import time; print(int(time.time() * 1000))')
    OUTPUT=$(ollama create "$model_name" -f "$modelfile" 2>&1)
    EXIT_CODE=$?
    END=$(python3 -c 'import time; print(int(time.time() * 1000))')
    ELAPSED=$((END - START))
    
    # Проверяем не упала ли Ollama
    if ! kill -0 $OLLAMA_PID 2>/dev/null; then
        echo "🔴 CRASH! Ollama упала!"
        RESULTS+=("🔴 CRASH: $name")
        echo "[!!!] OLLAMA CRASHED ON: $name" >> "$LOG_FILE"
        break
    fi
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ OK (${ELAPSED}ms)"
        RESULTS+=("✅ $name")
    elif [ $ELAPSED -gt 9000 ]; then
        echo "🟡 TIMEOUT (${ELAPSED}ms) — возможный hang!"
        RESULTS+=("🟡 TIMEOUT: $name")
    else
        echo "🔵 Error: $(echo "$OUTPUT" | grep -i error | head -1)"
        RESULTS+=("🔵 Error: $name")
    fi
    
    ollama rm "$model_name" 2>/dev/null
    sleep 0.5
done

echo ""
echo "=== ИТОГИ ==="
printf '%s\n' "${RESULTS[@]}"
echo ""
echo "[*] Полный лог: $LOG_FILE"
echo "[*] Grep для критичного: grep -E 'panic|fatal|crash|segfault' $LOG_FILE"

# Останавливаем слежку за логом
kill $TAIL_PID 2>/dev/null

echo ""
echo "[*] Восстанавливаю Homebrew service..."
kill $OLLAMA_PID 2>/dev/null
sleep 2
brew services start ollama

