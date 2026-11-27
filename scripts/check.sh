#!/usr/bin/env bash
# One-command check: attack suite + URL smoke test. Usage: bash scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY=python
[ -x .venv/bin/python ] && PY=.venv/bin/python
[ -x .venv/Scripts/python.exe ] && PY=.venv/Scripts/python.exe

"$PY" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:8000/api/users >/dev/null && break
  sleep 0.5
done

for u in / /v1/ /v2/ /shared/crypto.js /shared/dlp.js /shared/vendor/libsodium.js; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8000$u")
  echo "$u -> $code"
  [ "$code" = "200" ] || { echo "FAIL: $u"; exit 1; }
done

"$PY" attacks/run_all_attacks.py
echo "CHECK PASSED"
