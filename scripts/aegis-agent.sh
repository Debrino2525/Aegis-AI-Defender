#!/usr/bin/env bash
# Production launcher for the thin Aegis host collector.
#
#   ./scripts/aegis-agent.sh enroll --url https://CONSOLE:8000 --token TOKEN [--ca /path/to/ca.crt]
#   ./scripts/aegis-agent.sh heartbeat
#   ./scripts/aegis-agent.sh run
#   ./scripts/aegis-agent.sh install [--user] [--enable]
#   ./scripts/aegis-agent.sh uninstall [--user]
#   ./scripts/aegis-agent.sh start|stop|status [--user]
#
# install writes a systemd unit that runs `python -m aegis.agent run` with Restart=always.
# Enroll first; the unit only keeps an already-enrolled agent alive.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONUNBUFFERED=1
cd "$ROOT"

python_bin() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return
  fi
  if command -v python >/dev/null 2>&1; then
    command -v python
    return
  fi
  echo "Python 3.10+ is required on PATH." >&2
  exit 1
}

PY="$(python_bin)"
UNIT_NAME="aegis-agent.service"
USER_MODE=0

want_user() {
  for arg in "$@"; do
    if [[ "$arg" == "--user" ]]; then
      return 0
    fi
  done
  return 1
}

systemctl_cmd() {
  if [[ "$USER_MODE" -eq 1 ]]; then
    systemctl --user "$@"
  else
    systemctl "$@"
  fi
}

unit_path() {
  if [[ "$USER_MODE" -eq 1 ]]; then
    echo "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/${UNIT_NAME}"
  else
    echo "/etc/systemd/system/${UNIT_NAME}"
  fi
}

write_unit() {
  local dest="$1"
  local agent_dir="${AEGIS_AGENT_DIR:-$HOME/.aegis/agent}"
  local user_line=""
  local wanted="multi-user.target"
  if [[ "$USER_MODE" -eq 1 ]]; then
    wanted="default.target"
  elif [[ "${EUID:-$(id -u)}" -eq 0 ]] && getent passwd aegis >/dev/null 2>&1; then
    user_line="User=aegis
Group=aegis"
    agent_dir="${AEGIS_AGENT_DIR:-/var/lib/aegis/agent}"
  fi
  mkdir -p "$(dirname "$dest")"
  cat > "$dest" <<UNIT
[Unit]
Description=Aegis host agent
Documentation=file://${ROOT}/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${user_line}
WorkingDirectory=${ROOT}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${ROOT}
Environment=AEGIS_AGENT_DIR=${agent_dir}
ExecStart=${PY} -m aegis.agent run
Restart=always
RestartSec=5
TimeoutStopSec=20
KillSignal=SIGTERM

[Install]
WantedBy=${wanted}
UNIT
}

cmd="${1:-}"
shift || true
if want_user "$@"; then
  USER_MODE=1
fi

case "$cmd" in
  ""|-h|--help|help)
    sed -n '2,14p' "$0"
    exit 0
    ;;
  enroll|heartbeat|run)
    exec "$PY" -m aegis.agent "$cmd" "$@"
    ;;
  install)
    dest="$(unit_path)"
    if [[ "$USER_MODE" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "Root is required for a system unit. Re-run with --user, or sudo $0 install." >&2
      exit 1
    fi
    write_unit "$dest"
    echo "Wrote $dest"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl_cmd daemon-reload
      enable_now=0
      for arg in "$@"; do
        [[ "$arg" == "--enable" || "$arg" == "--now" ]] && enable_now=1
      done
      if [[ "$enable_now" -eq 1 ]]; then
        systemctl_cmd enable --now "$UNIT_NAME"
        echo "Enabled and started $UNIT_NAME"
      else
        echo "Next: $([[ "$USER_MODE" -eq 1 ]] && echo 'systemctl --user' || echo systemctl) enable --now $UNIT_NAME"
      fi
    else
      echo "systemd is not available on this host. Run: $0 run"
    fi
    ;;
  uninstall)
    dest="$(unit_path)"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl_cmd disable --now "$UNIT_NAME" 2>/dev/null || true
      systemctl_cmd daemon-reload || true
    fi
    rm -f "$dest"
    echo "Removed $dest"
    ;;
  start|stop|status)
    if ! command -v systemctl >/dev/null 2>&1; then
      echo "systemd is not available." >&2
      exit 1
    fi
    systemctl_cmd "$cmd" "$UNIT_NAME"
    ;;
  *)
    exec "$PY" -m aegis.agent "$cmd" "$@"
    ;;
esac
