#!/usr/bin/env bash
# Benchmark nang luc sinh goi SYN (pps) cua may host - chi dung trong lab co lap.
# Tra loi cau hoi "nen tang nay sinh goi nhanh bao nhieu" de so sanh Ubuntu vs Windows.
#
# Phuong phap 2 diem: do tong goi o T_SHORT va T_LONG giay roi lay hieu,
#   pps = (N_long - N_short) / (T_LONG - T_SHORT)
# -> khu chi phi khoi dong scapy (import + tao socket) ra khoi ket qua.
#
# Cach dung:
#   ./experiments/bench_syn_throughput.sh                 # 1 nguon + 6 nguon, co spoof
#   ./experiments/bench_syn_throughput.sh -s 6 -l 16      # chon T_SHORT/T_LONG
#   ./experiments/bench_syn_throughput.sh --no-spoof      # do ban khong spoof
set -euo pipefail

# --- tu re-exec duoi nhom docker neu khong truy cap duoc daemon ---
if ! docker version >/dev/null 2>&1; then
  if id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
    exec sg docker -c "$(printf '%q ' "$0" "$@")"
  fi
  echo "[!] Khong truy cap duoc Docker daemon va user khong o nhom 'docker'." >&2
  exit 1
fi

TARGET="172.30.0.10"
T_SHORT=6
T_LONG=16
SPOOF="--rand-source"
SRC_SET=(1 6)   # cac muc so nguon se do

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -s|--short)  T_SHORT="$2"; shift 2 ;;
    -l|--long)   T_LONG="$2"; shift 2 ;;
    --no-spoof)  SPOOF=""; shift ;;
    -n|--sources) SRC_SET=($2); shift 2 ;;   # vd: -n "1 3 6"
    *) echo "[!] Tham so la: $1" >&2; exit 2 ;;
  esac
done

ATTACKERS=(attacker1 attacker2 attacker3 attacker4 attacker5 attacker6)

# chay 1 attacker trong $2 giay, in ra tong goi (SIGINT de syn_flood in dong "tong goi")
run_one() { # $1=container $2=dur
  docker exec "$1" timeout -s INT "$2" hping3 -S -p 80 -q --flood $SPOOF "$TARGET" 2>&1 \
    | awk '/transmitted/{print $1}'
}

# chay $1 attacker song song trong $2 giay, tra ve tong goi cong don
run_n() { # $1=n $2=dur
  local n="$1" dur="$2" tmp i v sum=0
  tmp="$(mktemp -d)"
  for ((i=0; i<n; i++)); do
    run_one "${ATTACKERS[$i]}" "$dur" > "$tmp/$i" &
  done
  wait
  for ((i=0; i<n; i++)); do v="$(cat "$tmp/$i" 2>/dev/null || echo 0)"; sum=$((sum + ${v:-0})); done
  rm -rf "$tmp"
  echo "$sum"
}

echo "=== Benchmark SYN throughput (spoof=${SPOOF:-off}, T_SHORT=${T_SHORT}s T_LONG=${T_LONG}s) ==="
printf "%-8s %12s %12s %14s %14s\n" "nguon" "N@${T_SHORT}s" "N@${T_LONG}s" "pps_tong" "pps/nguon"
dt=$((T_LONG - T_SHORT))
for n in "${SRC_SET[@]}"; do
  ns="$(run_n "$n" "$T_SHORT")"
  nl="$(run_n "$n" "$T_LONG")"
  awk -v n="$n" -v ns="${ns:-0}" -v nl="${nl:-0}" -v dt="$dt" 'BEGIN{
    pps=(nl-ns)/dt;
    printf "%-8s %12d %12d %14.0f %14.0f\n", n, ns, nl, pps, pps/n;
  }'
done
echo "=== xong ==="
