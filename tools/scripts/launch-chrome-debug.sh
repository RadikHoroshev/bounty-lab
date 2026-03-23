#!/bin/bash
# Запускает Chrome с remote debugging — нужно для Control Chrome MCP
# Запускай ОДИН РАЗ перед началом работы с huntr

echo "🚀 Запускаю Chrome с remote debugging на порту 9222..."
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/Library/Application Support/Google/Chrome" \
  "https://huntr.com" 2>/dev/null &

sleep 2
curl -s http://localhost:9222/json/version | python3 -m json.tool 2>/dev/null | grep -E "Browser|webSocketDebugger" && echo "✅ Chrome готов" || echo "⏳ Chrome стартует..."
