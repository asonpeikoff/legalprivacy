#!/usr/bin/env bash
# Double-click (macOS: .command; Linux: "Run in terminal") to run legalPrivacy from source.
# Sets up a private environment on first run, and updates it whenever the requirements change.
#
#   ./start-legalprivacy.sh                    run it (opens the dashboard)
#   ./start-legalprivacy.sh --service          Linux: install it as a background service that starts when you log in
#                                              and keeps running with no window; the dashboard is still a web page
#   ./start-legalprivacy.sh --uninstall-service   remove that service again
#   ./start-legalprivacy.sh --url              print the dashboard link (for the service, or a running copy)
cd "$(dirname "$0")" || exit 1
PY=$(command -v python3 || command -v python) || { echo "Python 3.10+ is required."; read -r -p "Press Enter…"; exit 1; }
NEED=0
if [ ! -x .venv/bin/python ]; then
  echo "First run: setting things up, one moment…"
  "$PY" -m venv .venv || { echo "Could not create the environment"; read -r -p "Press Enter…"; exit 1; }
  NEED=1
fi
SUM=$(cksum pyproject.toml | cut -d' ' -f1)
[ "$(cat .venv/.installed 2>/dev/null)" = "$SUM" ] || NEED=1
if [ "$NEED" = 1 ]; then
  echo "Installing or updating what legalPrivacy needs…"
  .venv/bin/python -m pip install --quiet -e . || { echo "Install failed"; read -r -p "Press Enter…"; exit 1; }
  echo "$SUM" > .venv/.installed
fi
DIR=$(pwd)
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT="$UNIT_DIR/legalprivacy.service"
case "${1:-}" in
  --url)
    exec .venv/bin/python -m legalprivacy.launcher --url ;;
  --service)
    command -v systemctl >/dev/null 2>&1 || { echo "systemd was not found: --service needs a Linux system with systemd."; exit 1; }
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT" <<UNITEOF
[Unit]
Description=legalPrivacy (background noise, dashboard on 127.0.0.1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$DIR/.venv/bin/python -m legalprivacy --no-browser
Restart=on-failure
RestartSec=15
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
UNITEOF
    echo "Wrote $UNIT"
    systemctl --user daemon-reload && systemctl --user enable --now legalprivacy.service \
      || { echo "Could not start it with systemctl --user. The unit file is in place; try: systemctl --user enable --now legalprivacy"; exit 1; }
    loginctl enable-linger "$USER" 2>/dev/null \
      || echo "Note: to keep it running when you are logged out, run: sudo loginctl enable-linger $USER"
    sleep 3
    echo
    echo "legalPrivacy is now running as a background service."
    echo "Open the dashboard:  $(.venv/bin/python -m legalprivacy.launcher --url)"
    echo "Check it:            systemctl --user status legalprivacy"
    echo "See its messages:    journalctl --user -u legalprivacy -f"
    echo "Remove it:           ./start-legalprivacy.sh --uninstall-service"
    exit 0 ;;
  --uninstall-service)
    systemctl --user disable --now legalprivacy.service 2>/dev/null
    rm -f "$UNIT"
    systemctl --user daemon-reload 2>/dev/null
    echo "The legalPrivacy service was removed."
    exit 0 ;;
esac
exec .venv/bin/python -m legalprivacy "$@"
