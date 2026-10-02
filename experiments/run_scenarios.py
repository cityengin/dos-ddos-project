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
    "C": dict(desc="6 nguon HTTP flood (L7)",    truth="DDoS", mode="http", spoof=False, n=6, pps=0),
}


def dexec(container, *args, detach=False):
    cmd = ["docker", "exec"] + (["-d"] if detach else []) + [container] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def kill_all():
    dexec(DETECTOR, "pkill", "-f", "detector.py")
    for a in ATTACKERS:
        dexec(a, "pkill", "-f", "flood.py")


def run_one(name, baseline, duration, cooldown):
    s = SCEN[name]
    csv = f"/app/{name}.csv"
    host_csv = os.path.join(OUT_DIR, f"{name}.csv")
    print(f"\n=== Kich ban {name}: {s['desc']}  (mong doi: {s['truth']}) ===")

    kill_all()
    time.sleep(1)

    # 1) khoi dong detector (da sua: --victim = chi dem inbound)
    dexec(DETECTOR, "python3", "/app/detector.py", "--iface", "eth0",
          "--pps", "40", "--syn", "25", "--victim", VICTIM, "--csv", csv, detach=True)
    time.sleep(2)  # cho sniff khoi dong

    # 2) baseline truoc tan cong
    print(f"[*] baseline {baseline}s (mang yen tinh)...")
    time.sleep(baseline)

    # 3) tan cong
    t_start = dt.datetime.now().strftime("%H:%M:%S")
    used = ATTACKERS[:s["n"]]
    print(f"[*] TAN CONG {duration}s tu {len(used)} nguon: {', '.join(used)}")
    for a in used:
        if s["mode"] == "syn":
            cmd = ["timeout", str(duration), "python3", "/app/syn_flood.py", VICTIM, "-p", "80"]
            if s.get("pps"):
                cmd += ["--pps", str(s["pps"])]
            if s["spoof"]:
                cmd.append("--spoof")
        else:
            cmd = ["python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", "20", "-d", str(duration)]
        dexec(a, *cmd, detach=True)

    time.sleep(duration + 1)
    t_end = dt.datetime.now().strftime("%H:%M:%S")

    # 4) cooldown roi dung detector
    print(f"[*] cooldown {cooldown}s...")
    time.sleep(cooldown)
    kill_all()
    time.sleep(1)

    meta = dict(name=name, desc=s["desc"], truth=s["truth"], mode=s["mode"],
                spoof=s["spoof"], sources=used, victim=VICTIM,
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
    args = ap.parse_args()

    names = [args.only] if args.only else list(SCEN)
    for n in names:
        run_one(n, args.baseline, args.duration, args.cooldown)
    print("\n[*] HOAN TAT. CSV + meta trong thu muc detection/")


if __name__ == "__main__":
    main()
