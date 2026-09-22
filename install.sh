#!/usr/bin/env bash
# Install V.SCAN so plain `vscan` works (no venv activate needed).
#   sudo bash install.sh   → /usr/local/bin/vscan
#   bash install.sh        → ~/.local/bin/vscan
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv"

echo "[V.SCAN] project: $ROOT"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[V.SCAN] creating virtualenv…"
  python3 -m venv "$VENV"
fi

echo "[V.SCAN] installing package…"
"$VENV/bin/pip" install -U pip -q
"$VENV/bin/pip" install -e "$ROOT" -q

TARGET_BIN="$VENV/bin/vscan"
chmod +x "$TARGET_BIN"

if [[ "$(id -u)" -eq 0 ]]; then
  LINK="/usr/local/bin/vscan"
  ln -sfn "$TARGET_BIN" "$LINK"
  echo "[V.SCAN] OK — $LINK"
else
  mkdir -p "$HOME/.local/bin"
  LINK="$HOME/.local/bin/vscan"
  ln -sfn "$TARGET_BIN" "$LINK"
  echo "[V.SCAN] OK — $LINK"
  if ! echo ":$PATH:" | grep -q ":$HOME/.local/bin:"; then
    echo 'Add to ~/.bashrc:  export PATH="$HOME/.local/bin:$PATH"'
  fi
fi

echo
"$LINK" --version
echo "Try:  vscan   |   vscan help   |   vscan 192.168.1.0/24"
