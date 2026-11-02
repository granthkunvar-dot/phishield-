#!/usr/bin/env bash
# ==============================================================================
# Phishield Runner for macOS (Apple Silicon M1/M2/M3/M4/M5) & Linux
# ==============================================================================

# Activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run Phishield server
# Default port is 5001 to prevent clashes with macOS AirPlay Receiver on port 5000
python3 run.py

