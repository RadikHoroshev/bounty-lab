#!/bin/bash
# Huntr monitor - checks for new NLTK/MLflow/AI-ML bounties
# Runs via claudeclaw cron every 30 minutes

LOG="$HOME/projects/bounty-lab/tools/logs/huntr-monitor.log"
CACHE="$HOME/projects/bounty-lab/tools/cache/huntr-seen.txt"
TELEGRAM_BOT="$HOME/projects/bounty-lab/tools/scripts/telegram-notify.sh"

mkdir -p "$(dirname $LOG)" "$(dirname $CACHE)"

echo "[$(date)] Huntr monitor check" >> "$LOG"

# Check huntr hacktivity for new AI/ML bounties
# Uses curl to fetch the page (no auth needed for public feed)
RESPONSE=$(curl -s --max-time 15 \
  "https://huntr.com/bounties/hacktivity" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null | \
  grep -o '"title":"[^"]*"' | head -20)

if [ -z "$RESPONSE" ]; then
  echo "[$(date)] Failed to fetch huntr data" >> "$LOG"
  exit 1
fi

# Check for new entries not seen before
NEW_ENTRIES=$(echo "$RESPONSE" | while read line; do
  if ! grep -qF "$line" "$CACHE" 2>/dev/null; then
    echo "$line"
  fi
done)

if [ -n "$NEW_ENTRIES" ]; then
  echo "[$(date)] NEW BOUNTIES FOUND: $NEW_ENTRIES" >> "$LOG"
  echo "$NEW_ENTRIES" >> "$CACHE"
  
  # Send Telegram notification if configured
  if [ -f "$TELEGRAM_BOT" ] && [ -n "$TELEGRAM_BOT_TOKEN" ]; then
    bash "$TELEGRAM_BOT" "🎯 New huntr bounties: $NEW_ENTRIES"
  fi
else
  echo "[$(date)] No new entries" >> "$LOG"
fi
