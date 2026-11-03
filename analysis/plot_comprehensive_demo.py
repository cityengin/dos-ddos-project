#!/usr/bin/env python3
"""Tao bieu do timeline tong hop tat ca cac pha tan cong thuc nghiem xuat ra assets/demo.png.
Gom 5 pha dai dien day du cho cac vector L3 / L4 / L7 va DoS vs DDoS:
  - Pha A: DoS TCP SYN Flood (1 nguon, n_src = 1, H = 0)
  - Pha B: DDoS TCP SYN Flood (6 nguon + IP Spoofing, n_src ~1600, H > 10)
  - Pha C: DDoS UDP Flood (L4 Volumetric, udp_s ~2750 pps)
  - Pha D: DDoS ICMP Ping Flood (L3 Volumetric, pps ~2700, TCP/UDP = 0)
  - Pha E: DDoS HTTP Flood (L7 Application, ACK >> SYN, n_src = 6)
"""
import os
import csv
import datetime as dt
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINAL_DIR = os.path.join(ROOT, "results", "final")
OUT_PNG = os.path.join(ROOT, "assets", "demo.png")
OUT_CSV = os.path.join(ROOT, "detection", "demo.csv")

plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Liberation Sans"]
plt.rcParams["axes.unicode_minus"] = False


def load_csv(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "pps": float(r["pps"]),
                "syn": float(r["syn_s"]),
                "ack": float(r["ack_s"]),
                "udp": float(r.get("udp_s", 0)),
                "h_src": float(r["h_src"]),
                "n_src": int(r["n_src"]),
                "alert": r["alert"].strip(),
                "ml_verdict": r.get("ml_verdict", ""),
            })
    return rows


def build_composite_timeline():
    # Danh sach kich ban: (file_csv, ten_hien_thi)
    scenarios = [
        ("A.csv", "A: DoS SYN (1 nguồn)"),
        ("B.csv", "B: DDoS SYN (Spoofing)"),
        ("U.csv", "C: DDoS UDP Flood (L4)"),
        ("I.csv", "D: DDoS ICMP Ping Flood (L3)"),
        ("C.csv", "E: DDoS HTTP Flood (L7)"),
    ]
    
    composite_rows = []
    phase_regions = []
    
    # Baseline ban dau: 3 giay tinh
    for _ in range(3):
        composite_rows.append({
            "pps": 0.0, "syn": 0.0, "ack": 0.0, "udp": 0.0,
            "h_src": 0.0, "n_src": 0, "alert": "", "ml_verdict": "BENIGN"
        })
        
    for fname, label in scenarios:
        p = os.path.join(FINAL_DIR, fname)
        raw_rows = load_csv(p)
        # Loc bo cac giay baseline o dau va duoi neu co qua nhieu
        # Lay cac dong co tan cong (pps > 10) kem 1 giay truoc/sau
        atk_indices = [i for i, r in enumerate(raw_rows) if r["pps"] > 30]
        if atk_indices:
            start_i = max(0, atk_indices[0] - 1)
            end_i = min(len(raw_rows), atk_indices[-1] + 2)
            selected = raw_rows[start_i:end_i]
        else:
            selected = raw_rows
            
        start_sec = len(composite_rows)
        for r in selected:
            composite_rows.append(r)
        end_sec = len(composite_rows) - 1
        
        phase_regions.append((start_sec, end_sec, label))
        
        # Cooldown 3 giay mang yen tinh giua cac pha
        for _ in range(3):
            composite_rows.append({
                "pps": 0.0, "syn": 0.0, "ack": 0.0, "udp": 0.0,
                "h_src": 0.0, "n_src": 0, "alert": "", "ml_verdict": "BENIGN"
            })
            
    # Ghi file CSV hop nhat
    with open(OUT_CSV, "w", encoding="utf-8") as f:
        f.write("sec,pps,syn_s,ack_s,udp_s,h_src,n_src,alert,ml_verdict\n")
        for s, r in enumerate(composite_rows):
            f.write(f"{s},{r['pps']:.0f},{r['syn']:.0f},{r['ack']:.0f},{r['udp']:.0f},{r['h_src']:.3f},{r['n_src']},{r['alert']},{r['ml_verdict']}\n")
            
    print(f"[*] Da tao dataset tong hop {OUT_CSV} gom {len(composite_rows)} giay.")
    return composite_rows, phase_regions


def plot_demo(composite_rows, phase_regions):
    x = np.arange(len(composite_rows))
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13.5, 7.8), sharex=True, dpi=150)
    
    # ---------------- PANEL 1: TOC DO GOI (Symlog) ----------------
    pps = [r["pps"] for r in composite_rows]
    syn = [r["syn"] for r in composite_rows]
    ack = [r["ack"] for r in composite_rows]
    udp = [r["udp"] for r in composite_rows]
    
    ax1.plot(x, pps, label="pps (Tổng gói/s)", color="#0284c7", lw=2.2, zorder=3)
    ax1.plot(x, syn, label="syn/s (Gói TCP SYN)", color="#ef4444", lw=1.5, ls="--", zorder=5)
    ax1.plot(x, ack, label="ack/s (Gói TCP ACK)", color="#10b981", lw=1.5, ls="-.", zorder=5)
    ax1.plot(x, udp, label="udp/s (Gói UDP)", color="#f59e0b", lw=1.6, ls=":", zorder=6)
    
    ax1.set_yscale("symlog", linthresh=10)
    ax1.set_ylabel("Tốc độ gói (gói/giây, symlog)", fontsize=10.5, fontweight="bold")
    ax1.grid(True, which="both", alpha=0.3, linestyle=":")
    ax1.legend(bbox_to_anchor=(0.5, 1.02), loc="lower center", ncol=4, fontsize=9.5, framealpha=0.95, edgecolor="#cccccc")
    ax1.set_ylim(-1, 9000)
    
    # ---------------- PANEL 2: ENTROPY & SO NGUON ----------------
    h_src = [r["h_src"] for r in composite_rows]
    n_src = [r["n_src"] for r in composite_rows]
    
    ax2.plot(x, h_src, label="H(src) - Shannon Entropy nguồn", color="#8b5cf6", lw=2.0, zorder=4)
    ax2.set_ylabel("Shannon Entropy nguồn H(src) [bits]", fontsize=10.5, fontweight="bold", color="#6d28d9")
    ax2.tick_params(axis="y", labelcolor="#6d28d9")
    ax2.set_ylim(-0.5, 14.5)
    ax2.grid(True, alpha=0.3, linestyle=":")
    
    ax2b = ax2.twinx()
    ax2b.plot(x, n_src, label="n_src - Số lượng IP nguồn", color="#d97706", lw=1.4, ls="--", zorder=3)
    ax2b.set_ylabel("Số lượng IP nguồn phân biệt (n_src)", fontsize=10.5, fontweight="bold", color="#b45309")
    ax2b.tick_params(axis="y", labelcolor="#b45309")
    ax2b.set_yscale("symlog", linthresh=5)
    ax2b.set_ylim(-1, 5500)
    
    # Ghep legend panel 2
    l1, la1 = ax2.get_legend_handles_labels()
    l2, la2 = ax2b.get_legend_handles_labels()
    ax2.legend(l1 + l2, la1 + la2, loc="upper right", fontsize=9.5, framealpha=0.95, edgecolor="#cccccc")
    ax2.set_xlabel("Thời gian dòng sự kiện (giây từ đầu buổi diễn tập)", fontsize=10.5, fontweight="bold")
    
    # ---------------- TO VUNG CAC PHA TAN CONG ----------------
    for idx, (s, e, label) in enumerate(phase_regions):
        for ax in (ax1, ax2):
            ax.axvspan(s, e, color="#ef4444", alpha=0.08, zorder=1)
            
        mid_x = (s + e) / 2
        short_letter = label.split(":")[0]
        full_title = label.split(":")[1].strip()
        
        # Nhãn chữ to trên panel 1 (y = 4500)
        ax1.text(mid_x, 4200, f"Pha {short_letter}", ha="center", va="center",
                 fontsize=10, fontweight="bold", color="#991b1b",
                 bbox=dict(boxstyle="round,pad=0.25", fc="#fee2e2", ec="#f87171", lw=1, alpha=0.95))
        
        # Mô tả ngắn gọn dưới chân panel 1 (y = 1.3)
        ax1.text(mid_x, 1.3, full_title, ha="center", va="bottom",
                 fontsize=8.5, fontweight="bold", color="#7f1d1d", rotation=0)

    fig.suptitle("DÒNG THỜI GIAN THỰC NGHIỆM ĐA VECTOR: DoS / DDoS / TCP SYN / UDP / ICMP / HTTP",
                 fontsize=12.5, fontweight="bold", y=0.98)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(OUT_PNG, dpi=150)
    plt.close(fig)
    print(f"[*] Da luu {OUT_PNG}")


if __name__ == "__main__":
    rows, phases = build_composite_timeline()
    plot_demo(rows, phases)
