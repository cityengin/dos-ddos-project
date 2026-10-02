#!/usr/bin/env python3
"""DEMO phong thu Slowloris (L7 low-and-slow) - before/after. Chi dung trong lab.
Chay tren HOST:  python mitigation/demo_slowloris.py

Victim da duoc lam YEU (worker_connections thap trong victim/nginx.conf). Slowloris giu
nhieu ket noi mo -> can slot ket noi -> client HOP LE khong vao duoc (dich vu "chet").
Bat phong thu (client_header_timeout rot ket noi cham) -> client hop le hoi phuc.
"""
import os
import subprocess
import time
import urllib.request

VICTIM = "172.30.0.10"
URL = "http://localhost:8080/"
ATTACKERS = ["attacker1", "attacker2", "attacker3"]
CONF = os.path.join(os.path.dirname(__file__), "nginx", "default.conf")


def dexec(c, *a, detach=False):
    return subprocess.run(["docker", "exec"] + (["-d"] if detach else []) + [c] + list(a),
                          capture_output=True, text=True)


def probe(n):
    """Client hop le tu host: do ti le 200 + do tre."""
    ok = 0
    lat = []
    for _ in range(n):
        t0 = time.time()
        try:
            if urllib.request.urlopen(URL, timeout=3).getcode() == 200:
                ok += 1
                lat.append((time.time() - t0) * 1000)   # chi do tre request THANH CONG
        except Exception:
            pass
        time.sleep(0.3)
    return ok, n, (sum(lat) / len(lat) if lat else 0.0)


def slowloris(on):
    for a in ATTACKERS:
        if on:
            dexec(a, "python3", "/app/slowloris.py", VICTIM, "-p", "80", "-c", "40", "-d", "120", detach=True)
        else:
            dexec(a, "pkill", "-f", "slowloris")


def mitigation(on):
    if on:
        dexec("victim", "sh", "-c", "test -f /tmp/dconf.orig || cp /etc/nginx/conf.d/default.conf /tmp/dconf.orig")
        subprocess.run(["docker", "cp", CONF, "victim:/etc/nginx/conf.d/default.conf"], capture_output=True)
        dexec("victim", "nginx", "-s", "reload")
    else:
        dexec("victim", "sh", "-c", "test -f /tmp/dconf.orig && cp /tmp/dconf.orig /etc/nginx/conf.d/default.conf")
        dexec("victim", "nginx", "-s", "reload")


def main():
    print("=" * 56)
    print(" DEMO phong thu Slowloris (L7 low-and-slow)")
    print("=" * 56)
    print("[1] baseline (khong tan cong)...")
    base = probe(5)
    print("[2] Slowloris 3x40, CHUA phong thu (doi 5s)...")
    slowloris(True); time.sleep(5)
    nodef = probe(10)
    print("[3] Bat phong thu (client_header_timeout), doi 7s...")
    mitigation(True); time.sleep(7)
    withdef = probe(10)
    slowloris(False); mitigation(False)

    def line(name, r):
        ok, n, lat = r
        lt = ("%.0fms" % lat) if ok else "(service down)"
        print("  %-26s %2d/%d OK   latency~%s" % (name, ok, n, lt))

    print("\n----- KET QUA (trai nghiem client hop le) -----")
    line("Baseline (no attack)", base)
    line("Slowloris, NO defense", nodef)
    line("Slowloris, WITH defense", withdef)
    print("=> Slowloris lam dich vu CHET (client gan nhu khong vao duoc);")
    print("   bat client_header_timeout -> rot ket noi cham -> client hoi phuc.")
    print("   Luu y: Slowloris luu luong THAP nen detector dua tren nguong pps/syn KHONG bao -")
    print("   do la diem mu low-and-slow (service-health moi phat hien duoc).")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        names = ["Baseline", "No defense", "With defense"]
        pct = [100 * base[0] / base[1], 100 * nodef[0] / nodef[1], 100 * withdef[0] / withdef[1]]
        fig, ax = plt.subplots(figsize=(7, 4.2))
        bars = ax.bar(names, pct, color=["#2ca02c", "#d62728", "#2ca02c"])
        ax.set_ylim(0, 108); ax.set_ylabel("Legitimate client success (%)")
        ax.set_title("Slowloris (low-and-slow): service down -> defense recovers")
        for b, v in zip(bars, pct):
            ax.text(b.get_x() + b.get_width() / 2, v + 2, "%.0f%%" % v, ha="center", fontweight="bold")
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        os.makedirs("assets", exist_ok=True)
        fig.savefig("assets/slowloris_demo.png", dpi=130)
        print("\n[*] Da luu do thi: assets/slowloris_demo.png")
    except Exception as e:
        print("[!] Khong ve duoc do thi:", e)


if __name__ == "__main__":
    main()
