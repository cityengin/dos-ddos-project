#!/usr/bin/env python3
"""Tao cac bieu do truc quan hoa ket qua Hoc may (Machine Learning) cho thu muc assets/:
  1. assets/ml_f1_compare.png: So sanh hieu nang Luat nguong vs Random Forest (F1-score & Accuracy).
  2. assets/ml_confusion.png: Ma tran nham lan (Confusion Matrix) chi tiet cua Luat vs Mo hinh ML.
Du lieu lay truc tiep tu danh gia Leave-One-Run-Out (LORO) 3 fold tren tap 3,362 cua so thuc te.
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS_DIR = os.path.join(ROOT, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Liberation Sans"]
plt.rcParams["axes.unicode_minus"] = False


def plot_f1_compare():
    out_path = os.path.join(ASSETS_DIR, "ml_f1_compare.png")
    
    # Chi so tu ml/results/window_metrics.txt (LORO 3-fold)
    metrics = [
        "F1 Nhị phân\n(Phát hiện Tấn công)",
        "Độ chính xác Đa lớp\n(Multiclass Accuracy)",
        "Macro F1-Score\n(BENIGN / DoS / DDoS)"
    ]
    rule_scores = [0.883, 0.611, 0.627]
    rule_stds = [0.003, 0.000, 0.002]
    
    ml_scores = [0.996, 0.994, 0.994]
    ml_stds = [0.001, 0.000, 0.001]
    
    x = np.arange(len(metrics))
    width = 0.36
    
    fig, ax = plt.subplots(figsize=(8.8, 5.5), dpi=150)
    
    rects1 = ax.bar(x - width/2, rule_scores, width, yerr=rule_stds, capsize=4,
                    label="Luật ngưỡng cố định (Rule-based)", color="#ff7f0e", edgecolor="#b35400", alpha=0.92, lw=1.2)
    rects2 = ax.bar(x + width/2, ml_scores, width, yerr=ml_stds, capsize=4,
                    label="Học máy Random Forest (LORO 3-fold)", color="#1f77b4", edgecolor="#0b4a78", alpha=0.92, lw=1.2)
    
    ax.set_ylabel("Điểm số / Tỷ lệ (0.0 - 1.0)", fontsize=11, fontweight="bold")
    fig.suptitle("So sánh Hiệu năng: Luật Ngưỡng vs Mô hình Học máy Cửa sổ (10 Đặc trưng)",
                 fontsize=12, fontweight="bold", y=0.96)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=10, fontweight="bold")
    ax.set_ylim(0, 1.20)
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 0.99), fontsize=9.5, ncol=2,
              framealpha=0.95, edgecolor="#cccccc")
    
    # Gan nhan so lieu len dau moi cot
    def autolabel(rects, is_ml=False):
        for rect in rects:
            height = rect.get_height()
            pct_text = f"{height*100:.1f}% ({height:.3f})"
            color = "#0b4a78" if is_ml else "#b35400"
            ax.annotate(pct_text,
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 5),
                        textcoords="offset points",
                        ha="center", va="bottom",
                        fontsize=9, fontweight="bold", color=color)

    autolabel(rects1, is_ml=False)
    autolabel(rects2, is_ml=True)
    
    # Ghi chu danh gia LORO
    fig.text(0.5, 0.015,
             "Đánh giá độc lập bằng Leave-One-Run-Out (LORO) trên 3,362 cửa sổ mạng (1.0s / bước nhảy 0.5s)",
             ha="center", fontsize=8.5, fontstyle="italic", color="#555555")

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[*] Da luu {out_path}")


def plot_confusion_matrix():
    out_path = os.path.join(ASSETS_DIR, "ml_confusion.png")
    
    classes = ["BENIGN", "DDoS", "DoS"]
    
    # Ma tran nham lan tu ml/results/window_metrics.txt (3362 mau)
    cm_rule = np.array([
        [761, 363,   0],
        [ 15, 1292,  0],
        [165, 766,   0]
    ])
    
    cm_ml = np.array([
        [1123,    1,   0],
        [  12, 1294,   1],
        [   5,    0, 926]
    ])
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.5, 5.2), dpi=150)
    
    # Ve panel 1: Luat nguong
    im1 = ax1.imshow(cm_rule, interpolation="nearest", cmap=plt.cm.Oranges, vmin=0, vmax=1350)
    ax1.set_title("Luật Ngưỡng Cố định\n(Accuracy: 61.1% - Báo nhầm 1,129 mẫu)", fontsize=11, fontweight="bold", pad=10)
    tick_marks = np.arange(len(classes))
    ax1.set_xticks(tick_marks)
    ax1.set_yticks(tick_marks)
    ax1.set_xticklabels(classes, fontsize=9.5, fontweight="bold")
    ax1.set_yticklabels(classes, fontsize=9.5, fontweight="bold")
    ax1.set_xlabel("Nhãn dự đoán (Predicted)", fontsize=10, fontweight="bold")
    ax1.set_ylabel("Nhãn thực tế (True)", fontsize=10, fontweight="bold")
    
    thresh1 = cm_rule.max() / 2.
    for i in range(cm_rule.shape[0]):
        for j in range(cm_rule.shape[1]):
            val = cm_rule[i, j]
            pct = val / cm_rule[i].sum() * 100 if cm_rule[i].sum() > 0 else 0
            txt = f"{val}\n({pct:.1f}%)"
            ax1.text(j, i, txt, ha="center", va="center",
                     fontsize=9, fontweight="bold",
                     color="white" if val > thresh1 else "black")
    
    # Ve panel 2: ML Random Forest
    im2 = ax2.imshow(cm_ml, interpolation="nearest", cmap=plt.cm.Blues, vmin=0, vmax=1350)
    ax2.set_title("Học máy Random Forest (LORO)\n(Accuracy: 99.4% - Sai sót chỉ 19 mẫu)", fontsize=11, fontweight="bold", pad=10)
    ax2.set_xticks(tick_marks)
    ax2.set_yticks(tick_marks)
    ax2.set_xticklabels(classes, fontsize=9.5, fontweight="bold")
    ax2.set_yticklabels(classes, fontsize=9.5, fontweight="bold")
    ax2.set_xlabel("Nhãn dự đoán (Predicted)", fontsize=10, fontweight="bold")
    ax2.set_ylabel("Nhãn thực tế (True)", fontsize=10, fontweight="bold")
    
    thresh2 = cm_ml.max() / 2.
    for i in range(cm_ml.shape[0]):
        for j in range(cm_ml.shape[1]):
            val = cm_ml[i, j]
            pct = val / cm_ml[i].sum() * 100 if cm_ml[i].sum() > 0 else 0
            txt = f"{val}\n({pct:.1f}%)"
            ax2.text(j, i, txt, ha="center", va="center",
                     fontsize=9, fontweight="bold",
                     color="white" if val > thresh2 else "black")

    fig.suptitle("Ma trận Nhầm lẫn (Confusion Matrix): Kiểm chứng Khả năng Phân loại DoS / DDoS / Benign",
                 fontsize=12.5, fontweight="bold", y=0.98)
    
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[*] Da luu {out_path}")


if __name__ == "__main__":
    plot_f1_compare()
    plot_confusion_matrix()
