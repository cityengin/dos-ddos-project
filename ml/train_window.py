#!/usr/bin/env python3
"""Train model phan loai muc-CUA-SO (BENIGN/DoS/DDoS) tren dac trung CUA DETECTOR; so voi luat nguong.

Khac voi ml/train.py (chay tren CICDDoS2019, dac trung muc FLOW), file nay train tren chinh
dac trung detector tao ra moi cua so 1 giay (pps, syn_s, ack_s, H(src), H(dport), n_src + 2 ty le
dan xuat). Mot RandomForest DA LOP (nhi phan suy ra = du doan != BENIGN). Danh gia 2 cach:
  (a) split phan tang 70/30, (b) leave-one-run-out (giu nguyen tung lan chay ra test) -> F1 dang tin hon.
So voi luat project (pps>=40 or syn>=25; n_src>=2 -> DDoS else DoS). Luu model de detector dung live.

Chi dung trong lab. Chay tren HOST (can scikit-learn + joblib):
    .venv/bin/python ml/train_window.py
"""
import argparse, csv, os, datetime as dt
import numpy as np
import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score, classification_report, confusion_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "ml", "data", "windows.csv")
MODEL_OUT = os.path.join(ROOT, "detection", "window_model.joblib")
REPORT_OUT = os.path.join(ROOT, "ml", "results", "window_metrics.txt")

# Thu tu dac trung PHAI co dinh - detector live se dung dung thu tu nay de dung vector.
FEATURES = ["pps", "syn_s", "ack_s", "h_src", "h_dport", "n_src", "syn_ratio", "ack_syn_ratio"]
RULE_PPS, RULE_SYN = 40, 25   # nguong luat cua project (giong detector)


def load(path):
    rows = list(csv.DictReader(open(path)))
    X = np.array([[float(r[c]) for c in FEATURES] for r in rows], dtype=float)
    y = np.array([r["label"] for r in rows])
    runs = np.array([r["run"] for r in rows])
    return X, y, runs


def rule_predict(X):
    """Luat project tai moi cua so: trigger neu pps>=40 hoac syn>=25; n_src>=2 -> DDoS, else DoS;
    khong trigger -> BENIGN. (pps=col0, syn=col1, n_src=col5 theo FEATURES.)"""
    out = []
    for row in X:
        pps, syn, n_src = row[0], row[1], row[5]
        if pps >= RULE_PPS or syn >= RULE_SYN:
            out.append("DDoS" if n_src >= 2 else "DoS")
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
        raise SystemExit("Khong thay %s - chay 'python3 ml/build_window_dataset.py' truoc." % args.data)

    X, y, runs = load(args.data)
    classes = sorted(set(str(v) for v in y))   # ['BENIGN','DDoS','DoS'] (str thuong, khong phai np.str_)
    dist = {c: int((y == c).sum()) for c in classes}
    L = []
    L.append("Du lieu: %d window x %d dac trung | lop: %s" % (X.shape[0], X.shape[1], dist))
    L.append("Dac trung (thu tu co dinh): %s" % FEATURES)

    # ===== (a) split phan tang 70/30 =====
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    clf = new_rf(args.n_estimators); clf.fit(Xtr, ytr)
    ml = clf.predict(Xte)
    ru = rule_predict(Xte)

    L.append("\n===== (a) Split phan tang 70/30 (test = %d window) =====" % len(yte))
    L.append("Phat hien tan cong (nhi phan BENIGN vs attack) - F1:")
    L.append("  Luat nguong (pps>=%d or syn>=%d): F1 = %.3f" % (RULE_PPS, RULE_SYN, f1_score(binof(yte), binof(ru))))
    L.append("  RandomForest (window)           : F1 = %.3f" % f1_score(binof(yte), binof(ml)))
    L.append("Phan loai da lop (BENIGN/DoS/DDoS) - macro-F1:")
    L.append("  Luat nguong : macro-F1 = %.3f" % f1_score(yte, ru, average="macro", labels=classes, zero_division=0))
    L.append("  RandomForest: macro-F1 = %.3f" % f1_score(yte, ml, average="macro", labels=classes, zero_division=0))
    L.append("\nConfusion matrix RandomForest (hang=that, cot=du doan; nhan=%s):" % classes)
    L.append(str(confusion_matrix(yte, ml, labels=classes)))
    L.append("Confusion matrix Luat nguong:")
    L.append(str(confusion_matrix(yte, ru, labels=classes)))
    L.append("\nBao cao chi tiet RandomForest:")
    L.append(classification_report(yte, ml, digits=3, zero_division=0))

    # ===== recall tren window ATTACK DUOI NGUONG (luat bo sot) =====
    sub = [i for i in range(len(yte)) if yte[i] != "BENIGN" and Xte[i, 0] < RULE_PPS and Xte[i, 1] < RULE_SYN]
    L.append("Window ATTACK duoi nguong trong test (pps<%d va syn<%d): %d" % (RULE_PPS, RULE_SYN, len(sub)))
    if sub:
        ru_hit = sum(1 for i in sub if ru[i] != "BENIGN")
        ml_hit = sum(1 for i in sub if ml[i] != "BENIGN")
        L.append("  Luat bat dung 'attack': %d/%d (%.0f%%)" % (ru_hit, len(sub), 100.0 * ru_hit / len(sub)))
        L.append("  ML   bat dung 'attack': %d/%d (%.0f%%)  <-- diem ML hon luat" % (ml_hit, len(sub), 100.0 * ml_hit / len(sub)))

    # ===== (b) leave-one-run-out =====
    # Moi fold giu 1 lan chay ra test -> window gan-trung trong cung run khong nam ca 2 ben.
    # Dung F1 nhi phan + accuracy da lop (macro-F1 bi meo khi fold thieu lop) de do dang tin.
    ml_b, ml_a, ru_b, ru_a = [], [], [], []
    for r in sorted(set(runs)):
        te = runs == r
        c = new_rf(args.n_estimators); c.fit(X[~te], y[~te])
        p = c.predict(X[te]); rp = rule_predict(X[te])
        ml_b.append(f1_score(binof(y[te]), binof(p), zero_division=0)); ml_a.append(accuracy_score(y[te], p))
        ru_b.append(f1_score(binof(y[te]), binof(rp), zero_division=0)); ru_a.append(accuracy_score(y[te], rp))
    L.append("\n===== (b) Leave-one-run-out (%d fold) =====" % len(ml_b))
    L.append("  ML   : F1_bin = %.3f +/- %.3f | accuracy da lop = %.3f +/- %.3f" %
             (np.mean(ml_b), np.std(ml_b), np.mean(ml_a), np.std(ml_a)))
    L.append("  Luat : F1_bin = %.3f +/- %.3f | accuracy da lop = %.3f +/- %.3f" %
             (np.mean(ru_b), np.std(ru_b), np.mean(ru_a), np.std(ru_a)))

    report = "\n".join(L)
    print("\n" + report)

    # ===== train lai tren TOAN BO du lieu roi luu model de detector dung live =====
    final = new_rf(args.n_estimators); final.fit(X, y)
    bundle = {
        "model": final,
        "features": FEATURES,              # thu tu dac trung detector phai dung
        "labels": [str(c) for c in final.classes_],    # thu tu lop cho predict_proba (str thuong)
        "sklearn_version": sklearn.__version__,
        "created": dt.datetime.now().isoformat(timespec="seconds"),
        "n_train": int(X.shape[0]),
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump(bundle, args.out)
    os.makedirs(os.path.dirname(REPORT_OUT), exist_ok=True)
    open(REPORT_OUT, "w").write(report + "\n")
    print("\n[*] Da luu model: %s" % args.out)
    print("    sklearn=%s | labels=%s | features=%s" % (sklearn.__version__, [str(c) for c in final.classes_], FEATURES))
    print("[*] Da luu report: %s" % REPORT_OUT)
    print("[*] LUU Y Phase 3: container detector can sklearn==%s de nap model nay." % sklearn.__version__)


if __name__ == "__main__":
    main()
