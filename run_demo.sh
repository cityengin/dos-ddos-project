#!/usr/bin/env bash
# Script khoi chay toan bo cac kich ban tan cong cuong do cao (hping3 + ab)
# de theo doi Dashboard truc quan tai http://localhost:3000
set -euo pipefail

# Tu re-exec duoi nhom docker neu chua reload session
if ! docker version >/dev/null 2>&1; then
  if id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
    exec sg docker -c "$0 $*"
  fi
fi

python3 experiments/run_dashboard_demo.py "$@"
