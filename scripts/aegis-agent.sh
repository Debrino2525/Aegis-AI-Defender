#!/usr/bin/env bash
# Thin host collector. Enroll with a one-time token, then heartbeat.
# Usage:
#   ./scripts/aegis-agent.sh enroll --url http://CONSOLE:8000 --token TOKEN
#   ./scripts/aegis-agent.sh run
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec python3 -m aegis.agent "$@"
