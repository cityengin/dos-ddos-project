#!/usr/bin/env python3
"""DEMO trinh bay truoc giao vien: chay 1 lenh, co thuyet minh tung buoc.
Chi dung trong lab co lap. Chay tren HOST:  python experiments/demo.py

Kich ban: BINH THUONG -> DoS (1 nguon SYN) -> DDoS (3 nguon SYN spoof) -> DDoS (3 nguon HTTP L7).
Detector in bao dong realtime (stream truc tiep tu container); script thuyet minh + dieu khien tan cong.
"""
import subprocess, threading, time, sys, os

VICTIM = "172.30.0.10"
DETECTOR = "detector"
ATTACKERS = ["attacker1", "attacker2", "attacker3"]
NEEDED = ["victim", "detector", "attacker1", "attacker2", "attacker3"]
CLR = {"b": "\033[1m", "r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "0": "\033[0m"}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def dexec(container, *args, detach=False):
    cmd = ["docker", "exec"] + (["-d"] if detach else []) + [container] + list(args)
    return run(cmd)


def kill_all():
    dexec(DETECTOR, "pkill", "-f", "detector.py")
    for a in ATTACKERS:
        dexec(a, "pkill", "-f", "flood.py")


def say(msg, color="c"):
    print(f"\n{CLR[color]}{CLR['b']}>>> {msg}{CLR['0']}\n", flush=True)


def preflight():
    """Kiem tra Docker + cac container. Bao loi RO RANG neu thieu (khong chay ra rong)."""
    if run(["docker", "info"]).returncode != 0:
        print(CLR["r"] + CLR["b"] +
              "[X] Docker Desktop chua chay.\n"
              "    -> Mo Docker Desktop, doi bieu tuong chuyen XANH, roi chay lai demo." + CLR["0"])
        sys.exit(1)
    down = []
    for c in NEEDED:
        r = run(["docker", "inspect", "-f", "{{.State.Running}}", c])
        if r.returncode != 0 or r.stdout.strip() != "true":
            down.append(c)
    if down:
        print(CLR["r"] + CLR["b"] +
              f"[X] Lab chua san sang, container chua chay: {', '.join(down)}\n"
              "    -> Chay:  docker compose up -d   roi thu lai." + CLR["0"])
        sys.exit(1)
    print(CLR["g"] + "[*] Docker OK, lab dang chay: " + ", ".join(NEEDED) + CLR["0"])


def attack(mode, n, spoof, dur):
    for a in ATTACKERS[:n]:
        if mode == "syn":
            cmd = ["timeout", str(dur), "python3", "/app/syn_flood.py", VICTIM, "-p", "80"]
            if spoof:
                cmd.append("--spoof")
        else:
            cmd = ["python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", "20", "-d", str(dur)]
        r = dexec(a, *cmd, detach=True)
        if r.returncode != 0:
            print(CLR["r"] + f"[!] Khong khoi dong duoc tan cong tren {a}: {r.stderr.strip()}" + CLR["0"])


def stream_detector(proc):
    """In realtime tung dong detector, to mau theo nhan."""
    for line in proc.stdout:
        s = line.rstrip("\n")
        if "DDoS" in s:
            print(CLR["r"] + s + CLR["0"], flush=True)
        elif "DoS" in s:
            print(CLR["y"] + s + CLR["0"], flush=True)
        else:
            print(s, flush=True)


def main():
    banner_path = os.path.join(os.path.dirname(__file__), "..", "banner.txt")
    try:
        with open(banner_path, encoding="utf-8") as f:
            print(CLR["c"] + CLR["b"] + f.read() + CLR["0"])
    except OSError:
        print(CLR["b"] + "=" * 70 + "\n DEMO PHAT HIEN DoS/DDoS\n" + "=" * 70 + CLR["0"])
    print(CLR["b"] + " DEMO PHAT HIEN DoS/DDoS - lab co lap (victim 172.30.0.10)" + CLR["0"])

    preflight()
    kill_all()
    time.sleep(1)

    # detector chay ATTACHED, stdout stream thang ve day (khong qua file log)
    proc = subprocess.Popen(
        ["docker", "exec", DETECTOR, "python3", "-u", "/app/detector.py",
         "--iface", "eth0", "--pps", "40", "--syn", "25", "--victim", VICTIM, "--csv", "/app/demo.csv"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    threading.Thread(target=stream_detector, args=(proc,), daemon=True).start()
    time.sleep(2)
    if proc.poll() is not None:   # detector chet ngay -> loi
        print(CLR["r"] + "[X] Detector khong khoi dong duoc. Kiem tra container 'detector'." + CLR["0"])
        sys.exit(1)

    say("Cot: time | pkts/s | syn/s | ack/s | H(src) | H(dport) | ALERT", "c")
    say("[1] MANG BINH THUONG - khong tan cong (khong co bao dong)", "g")
    time.sleep(6)

    say("[2] DoS: 1 nguon SYN flood -> mong doi 'DoS [SYN flood]', n_src=1", "y")
    attack("syn", 1, False, 10); time.sleep(13)

    say("[3] DDoS: 3 nguon SYN + spoof IP -> mong doi 'DDoS [SYN flood]', H_src cao", "r")
    attack("syn", 3, True, 10); time.sleep(13)

    say("[4] DDoS: 3 nguon HTTP flood L7 -> mong doi 'DDoS', ACK >> SYN", "r")
    attack("http", 3, False, 10); time.sleep(13)

    say("[5] Tan cong ket thuc - mang tro lai binh thuong", "g")
    time.sleep(4)

    kill_all()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
    print(CLR["b"] + "\n[*] Demo xong. CSV: detection/demo.csv" + CLR["0"])

    # tu dong ve do thi - thu lan luot interpreter co matplotlib
    print("[*] Dang ve do thi -> analysis/demo.png ...")
    plot_args = ["analysis/plot_attack.py", "detection/demo.csv", "-o", "analysis/demo.png",
                 "--title", "DEMO: BinhThuong -> DoS(SYN) -> DDoS(SYN spoof) -> DDoS(HTTP L7)"]
    for c in [[sys.executable], ["py", "-3.13"], ["py", "-3"], ["python"], ["python3"]]:
        try:
            r = subprocess.run(c + plot_args, capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if r.returncode == 0:
            print(CLR["g"] + f"[*] Da tao analysis/demo.png (bang: {' '.join(c)})" + CLR["0"])
            break
    else:
        print(CLR["r"] + "[!] Chua ve duoc do thi (thieu matplotlib). Cai: pip install matplotlib" + CLR["0"])


if __name__ == "__main__":
    main()
