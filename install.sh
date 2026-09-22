#!/usr/bin/env bash
# Install V.SCAN so plain `vscan` works (clone can be deleted after install).
#   bash install.sh        → ~/.local/bin/vscan
#   sudo bash install.sh   → /usr/local/bin/vscan
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [[ "$(id -u)" -eq 0 ]]; then
  SHARE="/usr/local/share/vscan"
  LINK="/usr/local/bin/vscan"
else
  SHARE="${XDG_DATA_HOME:-$HOME/.local/share}/vscan"
  LINK="$HOME/.local/bin/vscan"
  mkdir -p "$(dirname "$LINK")"
fi

VENV="$SHARE/venv"

echo "[V.SCAN] source:  $ROOT"
echo "[V.SCAN] install: $SHARE"

# Prefer 3.12 / 3.11; refuse older runtimes (package requires >=3.11).
PY=""
for cand in python3.12 python3.11 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    PY="$cand"
    break
  fi
done
if [[ -z "$PY" ]]; then
  echo "[V.SCAN] ERROR: python3 not found. Install: sudo apt install -y python3 python3-venv" >&2
  exit 1
fi

VER="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
MAJOR="$("$PY" -c 'import sys; print(sys.version_info.major)')"
MINOR="$("$PY" -c 'import sys; print(sys.version_info.minor)')"
if [[ "$MAJOR" -lt 3 || ( "$MAJOR" -eq 3 && "$MINOR" -lt 11 ) ]]; then
  echo "[V.SCAN] ERROR: need Python 3.11+, found $VER ($PY)." >&2
  echo "         Ubuntu 22.04+: sudo apt install -y python3.11 python3.11-venv" >&2
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "[V.SCAN] WARN: nmap not in PATH — install: sudo apt install -y nmap" >&2
fi

echo "[V.SCAN] python: $PY ($VER)"
rm -rf "$SHARE"
mkdir -p "$SHARE"

echo "[V.SCAN] creating virtualenv…"
"$PY" -m venv "$VENV"

echo "[V.SCAN] installing package…"
"$VENV/bin/pip" install -U pip -q
"$VENV/bin/pip" install "$ROOT" -q

TARGET_BIN="$VENV/bin/vscan"
chmod +x "$TARGET_BIN"
ln -sfn "$TARGET_BIN" "$LINK"

echo "[V.SCAN] OK — $LINK → $TARGET_BIN"

if [[ "$(id -u)" -ne 0 ]]; then
  if ! echo ":$PATH:" | grep -q ":$HOME/.local/bin:"; then
    echo
    echo "[V.SCAN] Add this to ~/.bashrc (then: source ~/.bashrc):"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
  fi
fi

echo
"$LINK" --version
echo "Try:  vscan   |   vscan help   |   vscan 192.168.1.0/24"
