#!/usr/bin/env bash
# Convenience launcher for Linux/macOS: sets up deps on first run, then starts the UI.
set -e
cd "$(dirname "$0")"
python3 -c "import textual" 2>/dev/null || pip install -r requirements.txt
exec python3 sqlmap_ui.py "$@"
