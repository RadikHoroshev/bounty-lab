#!/bin/bash
# Bug bounty environment startup script
# Runs automatically on Claude Code session start

LOG="$HOME/.claude/bounty-startup.log"
echo "=== Bounty startup $(date) ===" >> "$LOG"

# 1. Launch Burp Suite if not running
if ! pgrep -f "BurpSuiteCommunity\|burpsuite" > /dev/null 2>&1; then
    echo "Starting Burp Suite..." >> "$LOG"
    open -a "Burp Suite Community Edition" 2>/dev/null &
    echo "Burp Suite launched" >> "$LOG"
else
    echo "Burp Suite already running" >> "$LOG"
fi

# 2. Launch Chrome with remote debugging if not already running with it
if ! pgrep -f "remote-debugging-port=9222" > /dev/null 2>&1; then
    echo "Starting Chrome with debug port 9222..." >> "$LOG"
    # Close existing Chrome first to avoid profile lock
    pkill -f "Google Chrome" 2>/dev/null
    sleep 1
    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
        --remote-debugging-port=9222 \
        --user-data-dir="$HOME/Library/Application Support/Google/Chrome" \
        "https://huntr.com" > /dev/null 2>&1 &
    echo "Chrome launched with debug port" >> "$LOG"
else
    echo "Chrome already running with debug port" >> "$LOG"
fi

echo "Startup complete" >> "$LOG"
