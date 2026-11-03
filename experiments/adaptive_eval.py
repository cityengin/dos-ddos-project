#!/usr/bin/env python3
"""So sanh NGUONG CO DINH vs NGUONG THICH NGHI (EWMA) tren chuoi tong hop.
Chay tren HOST (can numpy + matplotlib):  python experiments/adaptive_eval.py

Minh hoa dieu ma lab (baseline ~0) khong the hien duoc: khi luu luong hop le
TRÔI/biến thiên theo thoi gian, khong co nguong CO DINH nao vua bat duoc tan cong
vua khong bao dong gia; con nguong THICH NGHI lam duoc ca hai.
"""
import argparse
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---- cung logic voi detection/detector.py (--adaptive) ----
def adaptive_run(x, k=4.0, alpha=0.2, warmup=8, floor=50.0):
    mu = mad = 0.0
    thr_series, alerts = [], []
    for i, v in enumerate(x):
        thr = max(mu + k * mad, floor)
        triggered = i >= warmup and v > thr
        if not triggered:                      # chi hoc baseline khi khong bao dong
            mad = alpha * abs(v - mu) + (1 - alpha) * mad
            mu = alpha * v + (1 - alpha) * mu
        thr_series.append(thr)
        alerts.append(triggered)
    return np.array(thr_series), np.array(alerts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="assets/adaptive_eval.png")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)

    T = 180
    t = np.arange(T)
    # luu luong hop le: TRÔI tuyen tinh 100 -> 300 pps + nhieu Gauss
    legit = 100 + 200 * (t / T) + rng.normal(0, 12, T)
    pps = legit.copy()
    # tan cong (som, luc baseline con thap ~150): +150 pps
    atk = (t >= 35) & (t < 55)
    pps[atk] += 150
    pps = np.clip(pps, 0, None)

    FIXED_LOW, FIXED_HIGH = 200.0, 320.0
    thr_adap, alert_adap = adaptive_run(pps)
    alert_low = pps > FIXED_LOW
    alert_high = pps > FIXED_HIGH

    def score(alerts):
        detected = bool(alerts[atk].any())
        lat = int(np.argmax(alerts[atk])) if detected else None    # tre phat hien (giay)
        fp = int((alerts & ~atk).sum())                             # bao dong ngoai tan cong
        return detected, lat, fp

    rows = [("Fixed thap (200)", *score(alert_low)),
            ("Fixed cao  (320)", *score(alert_high)),
            ("Adaptive EWMA",    *score(alert_adap))]

    print("So sanh tren chuoi tong hop (baseline troi 100->300, tan cong t=35..55):")
    print("-" * 64)
    print(f"{'Phuong phap':<18}{'Bat tan cong?':<15}{'Tre(s)':<8}{'False positive':<14}")
    print("-" * 64)
    for name, det, lat, fp in rows:
        print(f"{name:<18}{('CO' if det else 'TRUOT (miss)'):<15}"
              f"{(str(lat) if lat is not None else '-'):<8}{fp:<14}")
    print("-" * 64)
    print("=> Fixed thap: bat duoc nhung bao dong gia luc luu luong hop le len cao.")
    print("=> Fixed cao : khong bao gia nhung TRUOT tan cong luc baseline thap.")
    print("=> Adaptive  : bat tan cong VA khong bao gia (nguong bam theo baseline).")

    # ---- do thi ----
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Liberation Sans"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, ax = plt.subplots(figsize=(11, 5.4), dpi=150)
    ax.plot(t, pps, color="#1f77b4", lw=1.8, label="Lưu lượng gói thực tế (pps)")
    ax.axhline(FIXED_LOW, color="#ff7f0e", ls="--", lw=1.4, label=f"Ngưỡng cố định thấp ({FIXED_LOW:.0f} pps)")
    ax.axhline(FIXED_HIGH, color="#9467bd", ls="--", lw=1.4, label=f"Ngưỡng cố định cao ({FIXED_HIGH:.0f} pps)")
    ax.plot(t, thr_adap, color="#2ca02c", lw=2.0, label="Ngưỡng thích nghi động (EWMA: $\\mu + k \\cdot \\mathrm{MAD}$)")
    ax.axvspan(35, 55, color="red", alpha=0.12)
    ax.set_ylim(40, 370)
    ax.text(45, 235, "TẤN CÔNG\n(t=35..55s)", ha="center", va="center",
            fontsize=9.5, fontweight="bold", color="#990000",
            bbox=dict(boxstyle="round,pad=0.35", fc="#ffebee", ec="#ef9a9a", lw=1.2))
    
    # danh dau false positive cua fixed-thap (luc luu luong hop le cao)
    fp_low = np.where(alert_low & ~atk)[0]
    ax.scatter(fp_low, pps[fp_low], s=22, color="#d9534f", zorder=5,
               label=f"Báo động nhầm (Ngưỡng thấp: {len(fp_low)} mẫu)", edgecolor="black", linewidth=0.5)
    
    ax.set_xlabel("Thời gian (giây)", fontsize=10, fontweight="bold")
    ax.set_ylabel("Tốc độ gói tin (gói/giây - pps)", fontsize=10, fontweight="bold")
    ax.set_title("So sánh Ngưỡng Cố định vs Ngưỡng Thích nghi EWMA khi Lưu lượng Nền Biến thiên",
                 fontsize=12, fontweight="bold", pad=12)
    ax.grid(True, alpha=0.3, linestyle=":")
    ax.legend(loc="upper left", fontsize=8.5, ncol=2, framealpha=0.92, edgecolor="#cccccc")
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("\n[*] Da luu do thi:", args.out)


if __name__ == "__main__":
    main()
