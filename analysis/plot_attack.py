#!/usr/bin/env python3
"""Ve do thi tu file CSV cua detector. Chi dung trong lab.

Vi du:
  python analysis/plot_attack.py detection/attack.csv -o analysis/attack.png
  python analysis/plot_attack.py detection/attack.csv --from 03:15:20 --to 03:15:40 -o analysis/scenarioC.png
"""
import argparse, csv, datetime as dt
import matplotlib
matplotlib.use("Agg")            # khong can GUI, xuat thang ra file
import matplotlib.pyplot as plt


def parse_time(s):
    return dt.datetime.strptime(s.strip(), "%H:%M:%S")


def load(path, t_from=None, t_to=None):
    rows = list(csv.DictReader(open(path)))
    t0 = parse_time(rows[0]["time"])
    out = []
    for r in rows:
        t = parse_time(r["time"])
        if t < t0:                     # qua nua dem -> cong 1 ngay
            t += dt.timedelta(days=1)
        if t_from and t < parse_time(t_from):
            continue
        if t_to and t > parse_time(t_to):
            continue
        out.append({
            "sec": (t - t0).total_seconds(),
            "pps": float(r["pps"]), "syn": float(r["syn_s"]), "ack": float(r["ack_s"]),
            "h_src": float(r["h_src"]), "n_src": int(r["n_src"]),
            "alert": r["alert"].strip(),
        })
    return out


def episodes(rows, gap=1):
    """Cac doan lien tuc co pps>0 (bo qua khe <=gap giay)."""
    eps, start, hole = [], None, 0
    for i, r in enumerate(rows):
        if r["pps"] > 0:
            if start is None:
                start = i
            hole = 0
        elif start is not None:
            hole += 1
            if hole > gap:
                eps.append((start, i - hole))
                start = None
    if start is not None:
        eps.append((start, len(rows) - 1))
    return eps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("-o", "--out", default="analysis/attack.png")
    ap.add_argument("--from", dest="t_from", default=None, help="HH:MM:SS")
    ap.add_argument("--to", dest="t_to", default=None, help="HH:MM:SS")
    ap.add_argument("--title", default=None)
    args = ap.parse_args()

    rows = load(args.csv, args.t_from, args.t_to)
    x = [r["sec"] for r in rows]
    eps = episodes(rows)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), sharex=True)

    # ----- panel 1: toc do goi (symlog de A/B/C khac bac deu doc duoc) -----
    ax1.plot(x, [r["pps"] for r in rows], label="pps",   color="#1f77b4", lw=1.4)
    ax1.plot(x, [r["syn"] for r in rows], label="syn/s", color="#d62728", lw=1.2)
    ax1.plot(x, [r["ack"] for r in rows], label="ack/s", color="#2ca02c", lw=1.2)
    ax1.set_yscale("symlog", linthresh=10)
    ax1.set_ylabel("goi / giay (symlog)")
    ax1.grid(True, which="both", alpha=0.25)
    ax1.legend(loc="upper right", ncol=3, fontsize=9)

    # ----- panel 2: entropy nguon + so nguon -----
    ax2.plot(x, [r["h_src"] for r in rows], label="H(src)", color="#9467bd", lw=1.6)
    ax2.set_ylabel("H(src) [bits]")
    ax2.grid(True, alpha=0.25)
    ax2b = ax2.twinx()
    ax2b.plot(x, [r["n_src"] for r in rows], label="n_src", color="#ff7f0e", lw=1.0, ls="--")
    ax2b.set_ylabel("n_src (so nguon)")
    ax2.set_xlabel("thoi gian (giay tu dau file)")
    l1, la1 = ax2.get_legend_handles_labels()
    l2, la2 = ax2b.get_legend_handles_labels()
    ax2.legend(l1 + l2, la1 + la2, loc="upper right", fontsize=9)

    # ----- to vung tan cong + nhan A/B/C -----
    for k, (s, e) in enumerate(eps):
        xs, xe = rows[s]["sec"], rows[e]["sec"]
        for ax in (ax1, ax2):
            ax.axvspan(xs, xe, color="red", alpha=0.08)
        lab = chr(ord("A") + k) if k < 26 else str(k)
        ax1.text((xs + xe) / 2, ax1.get_ylim()[1], f" {lab}",
                 ha="center", va="top", fontsize=10, fontweight="bold", color="#7a0000")

    fig.suptitle(args.title or f"Detector timeline - {args.csv}", fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    fig.savefig(args.out, dpi=130)
    print("[*] Da luu:", args.out, "| so vung tan cong:", len(eps))


if __name__ == "__main__":
    main()
