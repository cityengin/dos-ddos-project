#!/usr/bin/env python3
"""DEMO phong thu L7 (nginx rate-limit) - before/after. Chi dung trong lab.
Chay tren HOST:  python mitigation/demo_mitigation.py

Do 2 giai doan (HTTP flood tu 3 attacker + 1 client HOP LE tu host song song):
  BEFORE: nginx mac dinh (khong gioi han)
  AFTER : nginx co rate-limit per-IP (mitigation/nginx/default.conf)
So sanh: so request tan cong duoc phuc vu (200), va trai nghiem client hop le (ti le 200, do tre).
"""
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request

VICTIM = "172.30.0.10"
URL = "http://localhost:8080/"
ATTACKERS = ["attacker1", "attacker2", "attacker3"]
CONF_SRC = "mitigation/nginx/default.conf"
THREADS = 6
DUR = 6
C = {"b": "\033[1m", "g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "0": "\033[0m"}


def run(*a):
    return subprocess.run(list(a), capture_output=True, text=True)


def dexec(c, *a):
    return run("docker", "exec", c, *a)


def flood_all(threads, dur, res):
    counts = []
    lock = threading.Lock()

    def one(a):
        r = dexec(a, "python3", "/app/http_flood.py", VICTIM, "-p", "80", "-t", str(threads), "-d", str(dur))
        m = re.search(r"thanh cong:\s*(\d+)", r.stdout)
        with lock:
            counts.append(int(m.group(1)) if m else 0)

    ts = [threading.Thread(target=one, args=(a,)) for a in ATTACKERS]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    res["attack_200"] = sum(counts)


def legit_client(dur, res):
    end = time.time() + dur
    ok = n = 0
    lat = []
    while time.time() < end:
        t0 = time.time()
        try:
            code = urllib.request.urlopen(URL, timeout=3).getcode()
            ok += (code == 200)
        except Exception:
            pass
        lat.append((time.time() - t0) * 1000)
        n += 1
        time.sleep(0.3)
    res["legit_ok"], res["legit_n"] = ok, n
    res["legit_lat"] = sum(lat) / len(lat) if lat else 0.0


def phase(threads, dur):
    fr, lr = {}, {}
    tf = threading.Thread(target=flood_all, args=(threads, dur, fr))
    tl = threading.Thread(target=legit_client, args=(dur, lr))
    tf.start(); tl.start(); tf.join(); tl.join()
    return {**fr, **lr}


def apply_protected():
    dexec("victim", "cp", "/etc/nginx/conf.d/default.conf", "/tmp/orig.conf")
    run("docker", "cp", CONF_SRC, "victim:/etc/nginx/conf.d/default.conf")
    dexec("victim", "nginx", "-s", "reload")


def restore():
    dexec("victim", "cp", "/tmp/orig.conf", "/etc/nginx/conf.d/default.conf")
    dexec("victim", "nginx", "-s", "reload")


def preflight():
    if run("docker", "info").returncode != 0:
        sys.exit(C["r"] + "[X] Docker chua chay. Mo Docker Desktop roi thu lai." + C["0"])
    for c in ["victim"] + ATTACKERS:
        r = run("docker", "inspect", "-f", "{{.State.Running}}", c)
        if r.stdout.strip() != "true":
            sys.exit(C["r"] + f"[X] Container {c} chua chay. 'docker compose up -d' roi thu lai." + C["0"])
    if dexec("victim", "sh", "-c", "grep -c limit_req /etc/nginx/conf.d/default.conf || true").stdout.strip() not in ("0", ""):
        print(C["y"] + "[!] victim dang o cau hinh rate-limit. Tao lai cho sach..." + C["0"])
        run("docker", "compose", "up", "-d", "--force-recreate", "victim")
        time.sleep(3)


def main():
    print(C["b"] + "=" * 64 + "\n DEMO PHONG THU L7 - nginx rate-limit (before/after)\n" + "=" * 64 + C["0"])
    preflight()

    print(C["y"] + f"\n[1] BEFORE - nginx mac dinh (khong gioi han). Flood {DUR}s..." + C["0"])
    before = phase(THREADS, DUR)
    time.sleep(2)

    print(C["g"] + "\n[2] Bat phong thu: nginx rate-limit per-IP (10 r/s, burst 20)..." + C["0"])
    apply_protected()

    print(C["y"] + f"\n[3] AFTER - co rate-limit. Flood {DUR}s..." + C["0"])
    after = phase(THREADS, DUR)
    time.sleep(2)
    restore()
    print(C["g"] + "[*] Da khoi phuc nginx ve mac dinh." + C["0"])

    # ---- bang so sanh ----
    def pct(r):
        return 100.0 * r["legit_ok"] / r["legit_n"] if r["legit_n"] else 0.0
    print(C["b"] + "\n" + "-" * 64)
    print(f"{'':<26}{'BEFORE':>16}{'AFTER':>16}")
    print("-" * 64 + C["0"])
    print(f"{'Tan cong duoc phuc vu(200)':<26}{before['attack_200']:>16}{after['attack_200']:>16}")
    print(f"{'Client hop le: ti le 200':<26}{pct(before):>15.0f}%{pct(after):>15.0f}%")
    print(f"{'Client hop le: do tre(ms)':<26}{before['legit_lat']:>16.0f}{after['legit_lat']:>16.0f}")
    print("-" * 64)
    drop = 100.0 * (1 - after['attack_200'] / before['attack_200']) if before['attack_200'] else 0
    print(C["g"] + f"=> Rate-limit chan ~{drop:.1f}% request tan cong; client hop le van duoc phuc vu." + C["0"])

    # ---- do thi ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4.3))
        bars = ax.bar(["BEFORE\n(khong gioi han)", "AFTER\n(rate-limit)"],
                      [before["attack_200"], after["attack_200"]],
                      color=["#d62728", "#2ca02c"])
        ax.set_ylabel("So request tan cong duoc phuc vu (200)")
        ax.set_title("Phong thu L7: nginx rate-limit chan HTTP flood")
        ax.set_yscale("symlog")
        for b, v in zip(bars, [before["attack_200"], after["attack_200"]]):
            ax.text(b.get_x() + b.get_width() / 2, v, f" {v}", ha="center", va="bottom", fontweight="bold")
        fig.tight_layout()
        os.makedirs("assets", exist_ok=True)
        fig.savefig("assets/mitigation_demo.png", dpi=130)
        print("[*] Da luu do thi: assets/mitigation_demo.png")
    except Exception as e:
        print("[!] Khong ve duoc do thi:", e)


if __name__ == "__main__":
    main()
