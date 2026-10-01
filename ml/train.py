#!/usr/bin/env python3
"""Train + danh gia bo phan loai DDoS tren dac trung flow; so sanh ML vs luat nguong.

Chay voi du lieu mau (mac dinh):
    python ml/make_synthetic.py
    python ml/train.py

Chay voi CICDDoS2019 THAT (sau khi tai ve, vd mot file CSV flow):
    python ml/train.py --data path/to/CICDDoS2019.csv

Pipeline tu: chuan hoa ten cot, bo cot dinh danh, thay inf/NaN, chia train/test phan tang,
train RandomForest + HistGradientBoosting, va so sanh voi luat nguong 1 dac trung (baseline
giong detector luat cua project). Xuat bang metric + 2 do thi.
"""
import argparse
import glob
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import f1_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

ID_COLS = {"flow id", "source ip", "src ip", "destination ip", "dst ip", "source port",
           "src port", "destination port", "dst port", "protocol", "timestamp",
           "simillarhttp", "unnamed: 0", "flow byts/s", "flow bytes/s"}
RATE_HINTS = ["flow_pkts_s", "flow packets/s", "flow pkts/s", "pps"]


def _read_sampled(path, cap):
    """Doc 1 CSV theo chunk + lay mau de KHONG tran RAM voi file lon (vai GB).
    Uoc luong so dong tu kich thuoc file -> chon ti le lay mau ~ cap dong."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.readline()  # header
        lines = [f.readline() for _ in range(2000)]
    avg = sum(len(l) for l in lines) / max(1, len([l for l in lines if l]))
    est_rows = max(1, int(os.path.getsize(path) / max(1.0, avg)))
    frac = min(1.0, cap / est_rows) if cap else 1.0
    out = []
    for ch in pd.read_csv(path, chunksize=200000, low_memory=False):
        ch.columns = [c.strip() for c in ch.columns]
        out.append(ch if frac >= 1.0 else ch.sample(frac=frac, random_state=42))
    df = pd.concat(out, ignore_index=True) if out else pd.DataFrame()
    if cap and len(df) > cap:
        df = df.sample(cap, random_state=42).reset_index(drop=True)
    return df


def load(path, label_col, max_rows):
    # ho tro ca FILE lan THU MUC (nhieu CSV cua CICDDoS2019)
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.csv")))
        if not files:
            raise SystemExit(f"Thu muc {path} khong co file .csv nao.")
        per = max(3000, max_rows // len(files)) if max_rows else None
        print(f"[*] Doc {len(files)} file CSV trong {path} ...")
        df = pd.concat([_read_sampled(f, per) for f in files], ignore_index=True)
        if max_rows and len(df) > max_rows:
            df = df.sample(max_rows, random_state=42).reset_index(drop=True)
    else:
        df = _read_sampled(path, max_rows)
    # tim cot nhan
    lc = label_col or next((c for c in df.columns if c.lower() == "label"), None)
    if lc is None:
        raise SystemExit("Khong tim thay cot nhan (Label). Dung --label-col de chi dinh.")
    y = df[lc].astype(str).str.strip()
    # chon dac trung so, bo cot dinh danh
    drop = {lc.lower()} | ID_COLS
    feats = [c for c in df.columns if c.lower() not in drop]
    X = df[feats].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    keep = X.notna().all(axis=1)
    X, y = X.loc[keep], y.loc[keep]
    X = X.loc[:, X.nunique() > 1]           # bo cot hang so
    return X.reset_index(drop=True), y.reset_index(drop=True)


def pick_rate_col(X):
    for h in RATE_HINTS:
        for c in X.columns:
            if c.lower() == h:
                return c
    return X.var().idxmax()   # fallback: cot bien thien manh nhat


def rule_threshold(x_train, yb_train, x_test):
    """Luat nguong 1 dac trung: chon nguong tren tap train toi uu F1, ap len test."""
    qs = np.quantile(x_train, np.linspace(0.5, 0.995, 60))
    best_t, best_f1 = qs[0], -1
    for t in qs:
        f1 = f1_score(yb_train, (x_train > t).astype(int))
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return (x_test > best_t).astype(int), best_t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data/cicddos_style_sample.csv")
    ap.add_argument("--label-col", default=None)
    ap.add_argument("--max-rows", type=int, default=200000, help="gioi han dong (du lieu that rat lon)")
    ap.add_argument("--outdir", default="ml/results")
    args = ap.parse_args()

    if not os.path.exists(args.data):
        raise SystemExit(f"Khong thay {args.data}. Chay 'python ml/make_synthetic.py' truoc, "
                         f"hoac tro --data toi CSV CICDDoS2019 that.")
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs("assets", exist_ok=True)

    X, y = load(args.data, args.label_col, args.max_rows)
    yb = (y.str.upper() != "BENIGN").astype(int)          # nhan nhi phan: tan cong?
    print(f"[*] Du lieu: {X.shape[0]} dong x {X.shape[1]} dac trung | lop: {sorted(y.unique())}")

    Xtr, Xte, ytr, yte, ybtr, ybte = train_test_split(
        X, y, yb, test_size=0.3, random_state=42, stratify=y)

    # ---- baseline: luat nguong 1 dac trung (giong detector luat) ----
    rate_col = pick_rate_col(X)
    rule_pred, thr = rule_threshold(Xtr[rate_col].values, ybtr.values, Xte[rate_col].values)
    f1_rule = f1_score(ybte, rule_pred)

    # ---- ML (da lop) ----
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
        "HistGradientBoosting": HistGradientBoostingClassifier(random_state=42),
    }
    results = {}
    for name, clf in models.items():
        clf.fit(Xtr, ytr)
        pred = clf.predict(Xte)
        pred_bin = (pd.Series(pred).str.upper() != "BENIGN").astype(int).values
        results[name] = {
            "clf": clf, "pred": pred,
            "f1_bin": f1_score(ybte, pred_bin),                       # phat hien tan cong
            "f1_macro": f1_score(yte, pred, average="macro"),          # phan loai da lop
        }

    best = max(results, key=lambda m: results[m]["f1_bin"])

    # ---- bao cao ----
    lines = []
    lines.append("So sanh PHAT HIEN TAN CONG (nhi phan BENIGN vs tan cong) - F1:")
    lines.append(f"  Luat nguong 1 dac tr(%s > %.1f): F1 = %.3f" % (rate_col, thr, f1_rule))
    for name in results:
        lines.append(f"  {name:<22}: F1 = {results[name]['f1_bin']:.3f}   "
                     f"(macro-F1 da lop = {results[name]['f1_macro']:.3f})")
    lines.append("")
    lines.append(f"Bao cao chi tiet ({best}) - phan loai da lop:")
    lines.append(classification_report(yte, results[best]["pred"], digits=3))
    # feature importance (neu co)
    clf_best = results[best]["clf"]
    if hasattr(clf_best, "feature_importances_"):
        imp = pd.Series(clf_best.feature_importances_, index=X.columns).sort_values(ascending=False)
        lines.append("Top dac trung quan trong:")
        lines.append(imp.head(8).round(3).to_string())
    report = "\n".join(lines)
    print("\n" + report)
    with open(os.path.join(args.outdir, "metrics.txt"), "w", encoding="utf-8") as f:
        f.write(report + "\n")

    # ---- do thi 1: so sanh F1 phat hien tan cong ----
    names = ["Luat nguong"] + list(results.keys())
    vals = [f1_rule] + [results[n]["f1_bin"] for n in results]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(names, vals, color=["#ff7f0e", "#1f77b4", "#2ca02c"])
    ax.set_ylim(0, 1.05); ax.set_ylabel("F1 (phat hien tan cong)")
    ax.set_title("ML vs luat nguong - F1 phat hien tan cong")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center", fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout(); fig.savefig("assets/ml_f1_compare.png", dpi=130)

    # ---- do thi 2: confusion matrix (model tot nhat, da lop) ----
    fig, ax = plt.subplots(figsize=(6.2, 5.2))
    cm = confusion_matrix(yte, results[best]["pred"], labels=clf_best.classes_)
    ConfusionMatrixDisplay(cm, display_labels=clf_best.classes_).plot(
        ax=ax, cmap="Blues", colorbar=False, xticks_rotation=30)
    ax.set_title(f"Confusion matrix - {best}")
    fig.tight_layout(); fig.savefig("assets/ml_confusion.png", dpi=130)

    print(f"\n[*] Da luu: assets/ml_f1_compare.png, assets/ml_confusion.png, {args.outdir}/metrics.txt")


if __name__ == "__main__":
    main()
