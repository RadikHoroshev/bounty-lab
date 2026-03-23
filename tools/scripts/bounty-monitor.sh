#!/bin/bash
# Bounty research tmux monitor
# Usage: bash bounty-monitor.sh [--attach]

SESSION="bounty"

# Kill existing session
tmux kill-session -t "$SESSION" 2>/dev/null

# Create session with windows
tmux new-session  -d -s "$SESSION" -n "targets"
tmux new-window   -t "$SESSION" -n "mitmproxy"
tmux new-window   -t "$SESSION" -n "nuclei"
tmux new-window   -t "$SESSION" -n "logs"

# targets: show running docker containers
tmux send-keys -t "$SESSION:targets" \
  'docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not running"' Enter

# mitmproxy: ready-to-run hint
tmux send-keys -t "$SESSION:mitmproxy" \
  'echo "Launch: mitmdump -s ~/projects/bounty-lab/tools/scripts/mitm-intercept.py --listen-port 8080 --ssl-insecure"' Enter

# nuclei: ready-to-run hint
tmux send-keys -t "$SESSION:nuclei" \
  'echo "Launch: nuclei -target http://localhost:3000 -tags cve,oast,rce,sqli,ssrf -severity medium,high,critical"' Enter

# logs: tail startup log
tmux send-keys -t "$SESSION:logs" \
  'tail -f ~/.claude/bounty-startup.log 2>/dev/null || echo "No startup log yet. Start a new Claude session."' Enter

# Go back to first window
tmux select-window -t "$SESSION:targets"

echo "✓ Bounty monitor started."
echo "  Attach:  tmux attach -t $SESSION"
echo "  Windows: targets | mitmproxy | nuclei | logs"

if [[ "$1" == "--attach" ]]; then
  tmux attach -t "$SESSION"
fi
