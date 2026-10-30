#!/usr/bin/env python3
"""Train model phan loai muc-CUA-SO (BENIGN/DoS/DDoS) tren dac trung CUA DETECTOR; so voi luat.

Khac ml/train.py (CICDDoS2019, dac trung muc FLOW), file nay train tren chinh dac trung
detector tao moi cua so, lay tu dataset PCAP (pcap_to_windows.py) da gan nhan theo timeline.

Danh gia DUY NHAT bang LEAVE-ONE-RUN-OUT (LORO): 1 pcap = 1 run = 1 fold. KHONG dung split
ngau nhien 70/30 nua, vi cua so TRUOT GOI DAU (window 1.0s / stride 0.5s) khien 2 cua so ke
nhau chung ~50% goi -> split ngau nhien se ro ri (window gan-trung nam ca train lan test ->
metric ao cao). LORO giu tron mot run ra test nen khong ro ri.

FEATURES import tu detection/window_features.py (nguon-chan-ly dung chung voi detector live).

Chi dung trong lab. Chay tren HOST (can scikit-learn + joblib):
    .venv/bin/python ml/train_window.py --data ml/data/windows_pcap.csv
"""
import argparse
import csv
import datetime as dt
import os
import sys

import numpy as np
import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, accuracy_score, classification_report, confusion_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))   # de import window_features (dung chung)
import window_features as wf   # noqa: E402

DATA = os.path.join(ROOT, "ml", "data", "windows_pcap.csv")   # dataset moi (duong pcap)
MODEL_OUT = os.path.join(ROOT, "detection", "window_model.joblib")
REPORT_OUT = os.path.join(ROOT, "ml", "results", "window_metrics.txt")

# Thu tu dac trung CO DINH - import tu module dung chung (KHONG tu khai lai).
FEATURES = wf.FEATURES
RULE_PPS, RULE_SYN = 40, 25   # nguong luat cua project (giong detector)

# chi muc cot theo TEN (khong hardcode so) -> doi thu tu FEATURES khong vo luat
I_PPS = FEATURES.index("pps")
I_SYN = FEATURES.index("syn_s")
I_NSRC = FEATURES.index("n_src")


def load(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        missing = [c for c in FEATURES + ["label", "run"] if c not in reader.fieldnames]
        if missing:
            raise SystemExit(
                "[X] %s thieu cot: %s\n    (CSV nay co the tu build_window_dataset.py cu - thieu "
                "udp_s/rate_per_src. Dung ml/pcap_to_windows.py de tao dataset moi.)" % (path, missing))
        rows = list(reader)
    X = np.array([[float(r[c]) for c in FEATURES] for r in rows], dtype=float)
    y = np.array([r["label"] for r in rows])
    runs = np.array([r["run"] for r in rows])
    return X, y, runs


def rule_predict(X):
    """Luat NAIVE lam BASELINE so sanh: trigger neu pps>=40 hoac syn>=25; n_src>=2 -> DDoS, else DoS;
    khong trigger -> BENIGN. (Day la luat don gian; detector THUC TE dung them 'dominance'/top_share -
    khong co trong vector dac trung nay nen baseline giu ban naive de so voi ML.)"""
    out = []
    for row in X:
        if row[I_PPS] >= RULE_PPS or row[I_SYN] >= RULE_SYN:
            out.append("DDoS" if row[I_NSRC] >= 2 else "DoS")
        else:
            out.append("BENIGN")
    return np.array(out)


def binof(y):
    return (np.asarray(y) != "BENIGN").astype(int)


def new_rf(n):
    # class_weight balanced vi lop hoi lech; random_state co dinh de tai lap
    return RandomForestClassifier(n_estimators=n, class_weight="balanced",
                                  random_state=42, n_jobs=-1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--out", default=MODEL_OUT)
    ap.add_argument("--n-estimators", type=int, default=200)
    args = ap.parse_args()

    if not os.path.exists(args.data):
        raise SystemExit("Khong thay %s - chay 'python3 ml/pcap_to_windows.py ...' truoc "
                         "(hoac build_window_dataset.py cu lam fallback)." % args.data)

    X, y, runs = load(args.data)
    classes = sorted(set(str(v) for v in y))
    dist = {c: int((y == c).sum()) for c in classes}
    uniq_runs = sorted(set(runs))
    L = []
    L.append("Du lieu: %d window x %d dac trung | lop: %s" % (X.shape[0], X.shape[1], dist))
    L.append("Dac trung (thu tu co dinh, tu window_features.FEATURES): %s" % FEATURES)
    L.append("So run (pcap) cho LORO: %d -> %s" % (len(uniq_runs), uniq_runs))
    if len(uniq_runs) < 2:
        L.append("[!] CANH BAO: LORO can >=2 run (>=2 pcap thu o thoi diem khac nhau). Hien chi %d."
                 % len(uniq_runs))

    # ===== LEAVE-ONE-RUN-OUT (danh gia duy nhat) =====
    # Moi fold giu 1 run ra test -> window gan-trung trong cung run khong nam ca 2 ben.
    # F1 nhi phan + accuracy da lop (macro-F1 bi meo khi fold thieu lop).
    ml_b, ml_a, ru_b, ru_a = [], [], [], []
    y_true_all, y_ml_all, y_ru_all = [], [], []
    for r in uniq_runs:
        te = runs == r
        if te.sum() == 0 or (~te).sum() == 0:
            continue
        c = new_rf(args.n_estimators)
        c.fit(X[~te], y[~te])
        p = c.predict(X[te])
        rp = rule_predict(X[te])
        ml_a.append(accuracy_score(y[te], p))
        ru_a.append(accuracy_score(y[te], rp))
        if binof(y[te]).sum() > 0:   # fold co mau tan cong moi tinh F1 nhi phan
            ml_b.append(f1_score(binof(y[te]), binof(p), zero_division=0))
            ru_b.append(f1_score(binof(y[te]), binof(rp), zero_division=0))
        y_true_all += list(y[te]); y_ml_all += list(p); y_ru_all += list(rp)

    L.append("\n===== Leave-one-run-out (%d fold; F1_bin tren %d fold co tan cong) ====="
             % (len(ml_a), len(ml_b)))
    if ml_b:
        L.append("  ML   : F1_bin = %.3f +/- %.3f | accuracy da lop = %.3f +/- %.3f" %
                 (np.mean(ml_b), np.std(ml_b), np.mean(ml_a), np.std(ml_a)))
        L.append("  Luat : F1_bin = %.3f +/- %.3f | accuracy da lop = %.3f +/- %.3f" %
                 (np.mean(ru_b), np.std(ru_b), np.mean(ru_a), np.std(ru_a)))

    # gop du doan tat ca fold -> confusion + recall window DUOI NGUONG (luat bo sot)
    if y_true_all:
        yt = np.array(y_true_all); ym = np.array(y_ml_all); yr = np.array(y_ru_all)
        L.append("\nConfusion matrix ML (gop LORO; hang=that, cot=du doan; nhan=%s):" % classes)
        L.append(str(confusion_matrix(yt, ym, labels=classes)))
        L.append("Confusion matrix Luat (gop LORO):")
        L.append(str(confusion_matrix(yt, yr, labels=classes)))
        L.append("\nBao cao chi tiet ML (gop LORO):")
        L.append(classification_report(yt, ym, digits=3, zero_division=0))

    # ===== train lai tren TOAN BO -> luu model + in feature-importance =====
    final = new_rf(args.n_estimators)
    final.fit(X, y)
    imp = sorted(zip(FEATURES, final.feature_importances_), key=lambda kv: -kv[1])
    L.append("Feature importance (RandomForest tren toan bo du lieu):")
    for name, v in imp:
        L.append("  %-16s %.4f" % (name, v))

    report = "\n".join(L)
    print("\n" + report)

    bundle = {
        "model": final,
        "features": FEATURES,
        "labels": [str(c) for c in final.classes_],
        "sklearn_version": sklearn.__version__,
        "created": dt.datetime.now().isoformat(timespec="seconds"),
        "n_train": int(X.shape[0]),
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump(bundle, args.out)
    os.makedirs(os.path.dirname(REPORT_OUT), exist_ok=True)
    open(REPORT_OUT, "w").write(report + "\n")
    print("\n[*] Da luu model: %s" % args.out)
    print("    sklearn=%s | labels=%s | features=%s" % (sklearn.__version__, bundle["labels"], FEATURES))
    print("[*] Da luu report: %s" % REPORT_OUT)
    print("[!] LUU Y wire LIVE: FEATURES gom 'udp_s' va 'rate_per_src'. Truoc khi dung model nay voi "
          "detector --ml, phai them 2 khoa do vao feat dict trong detector.py (hien dung 8 khoa cu) - "
          "ca hai deu tinh duoc live (udp_s co san; rate_per_src = pps/max(n_src,1)).")


if __name__ == "__main__":
    main()
