#!/usr/bin/env python3
"""Sinh dataset muc-CUA-SO co nhan de train model ML live cho detector. Chi dung trong lab co lap.

Y tuong: detector hien chi co dac trung muc CUA SO (pps, syn_s, ack_s, H(src), H(dport), n_src),
KHONG co dac trung muc flow nhu CICDDoS2019. Nen ta train model moi tren CHINH dac trung do,
dung du lieu tu lab.

Cach lam:
  - Chay run_scenarios.py nhieu lan (da dang --duration/--pps) -> moi lan ghi detection/X.csv + meta.
  - Vi detector mo CSV bang che do "w" (ghi de) nen moi lan chay se de len file cu
    -> ta COPY ngay tung lan ra ml/data/raw/X_<tag>.csv truoc khi lan sau de len.
  - Gan nhan tung dong: BENIGN neu pps==0, nguoc lai = truth cua kich ban (DoS/DDoS).
    (Dung pps thay vi khoang thoi gian trong meta vi CSV ghi gio UTC trong container con
     meta ghi gio host (+7) -> lech mui gio; va trong lab baseline pps=0 tuyet doi nen
     pps>0 <=> dang co tan cong. Cach nay con tu gom cac window "ria" pps thap vao attack.)
  - Them dac trung dan xuat: syn_ratio = syn_s/max(pps,1), ack_syn_ratio = ack_s/max(syn_s,1).
  - Xuat ml/data/windows.csv + in thong ke can bang lop.

Chay (can quyen docker vi run_scenarios goi 'docker exec'):
  sg docker -c 'python3 ml/build_window_dataset.py'
  sg docker -c 'python3 ml/build_window_dataset.py --skip-run'   # chi gom lai tu raw da co
"""
import argparse, csv, json, os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # thu muc goc repo
DET_DIR = os.path.join(ROOT, "detection")
RAW_DIR = os.path.join(ROOT, "ml", "data", "raw")
OUT_CSV = os.path.join(ROOT, "ml", "data", "windows.csv")
RUNNER = os.path.join(ROOT, "experiments", "run_scenarios.py")

# Ma tran chay mac dinh: (kich ban, duration, pps|None).
# Cac dong pps thap (A pps15/20, B pps3) co tinh TAO window tan cong DUOI nguong luat (40/25)
# -> day la cho ML co co hoi hon luat o Phase 2.
MATRIX = [
    ("A", 20, 150), ("A", 20, 15), ("A", 15, 20),
    ("B", 20, 400), ("B", 20, 3),
    ("C", 20, None), ("C", 15, None),
]

OUT_HEADER = ["time", "scenario", "pps", "syn_s", "ack_s", "h_src", "h_dport", "n_src",
              "syn_ratio", "ack_syn_ratio", "label"]

# nguong luat cua project (de dem window attack duoi nguong)
RULE_PPS, RULE_SYN = 40, 25


def run_scenario(name, duration, pps, baseline, cooldown):
    cmd = [sys.executable, RUNNER, "--only", name, "--duration", str(duration),
           "--baseline", str(baseline), "--cooldown", str(cooldown)]
    if pps is not None:
        cmd += ["--pps", str(pps)]
    print("\n[*] chay:", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def label_file(csv_path, meta_path, scenario, writer):
    """Doc 1 CSV detector, gan nhan tung dong, ghi ra writer. Tra (so_dong, dict dem nhan)."""
    with open(meta_path) as f:
        truth = json.load(f).get("truth", "?")
    n, counts = 0, {}
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            try:
                pps = float(row["pps"]); syn = float(row["syn_s"]); ack = float(row["ack_s"])
            except (KeyError, ValueError):
                continue  # bo dong hong
            label = "BENIGN" if pps == 0 else truth
            syn_ratio = syn / max(pps, 1.0)
            ack_syn_ratio = ack / max(syn, 1.0)
            writer.writerow([row["time"], scenario, int(pps), int(syn), int(ack),
                             row["h_src"], row["h_dport"], row["n_src"],
                             "%.4f" % syn_ratio, "%.4f" % ack_syn_ratio, label])
            counts[label] = counts.get(label, 0) + 1
            n += 1
    return n, counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=int, default=6)
    ap.add_argument("--cooldown", type=int, default=5)
    ap.add_argument("--skip-run", action="store_true",
                    help="khong chay lab, chi gom lai tu ml/data/raw da co")
    args = ap.parse_args()

    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

    raw_items = []  # (csv_path, meta_path, scenario)
    if args.skip_run:
        for fn in sorted(os.listdir(RAW_DIR)):
            if fn.endswith(".csv"):
                meta = os.path.join(RAW_DIR, fn[:-4] + ".meta.json")
                if os.path.exists(meta):
                    raw_items.append((os.path.join(RAW_DIR, fn), meta, fn.split("_")[0]))
        if not raw_items:
            raise SystemExit("[X] ml/data/raw rong - bo --skip-run de chay lab truoc.")
    else:
        for i, (name, dur, pps) in enumerate(MATRIX, 1):
            run_scenario(name, dur, pps, args.baseline, args.cooldown)
            tag = "run%02d_d%s_p%s" % (i, dur, pps if pps is not None else "def")
            dst_csv = os.path.join(RAW_DIR, "%s_%s.csv" % (name, tag))
            dst_meta = os.path.join(RAW_DIR, "%s_%s.meta.json" % (name, tag))
            shutil.copy(os.path.join(DET_DIR, name + ".csv"), dst_csv)
            shutil.copy(os.path.join(DET_DIR, name + ".meta.json"), dst_meta)
            raw_items.append((dst_csv, dst_meta, name))

    # gom + gan nhan
    total, agg = 0, {}
    with open(OUT_CSV, "w", newline="") as out:
        w = csv.writer(out, lineterminator="\n")   # LF kieu Unix (tranh \r dinh vao cot cuoi)
        w.writerow(OUT_HEADER)
        for csv_path, meta_path, scenario in raw_items:
            n, counts = label_file(csv_path, meta_path, scenario, w)
            total += n
            for k, v in counts.items():
                agg[k] = agg.get(k, 0) + v
            print("    %-34s -> %4d dong  %s" % (os.path.basename(csv_path), n, dict(sorted(counts.items()))))

    # thong ke can bang lop
    print("\n[*] Tong: %d window -> %s" % (total, OUT_CSV))
    print("[*] Can bang lop:")
    for k in sorted(agg):
        print("      %-8s %5d  (%.1f%%)" % (k, agg[k], 100.0 * agg[k] / max(total, 1)))
    if agg:
        mx, mn = max(agg.values()), min(agg.values())
        ratio = mx / max(mn, 1)
        if mn == 0 or ratio > 5:
            print("[!] CANH BAO: lop mat can bang (ty le %.1fx). Nen chay them kich ban cho lop thieu." % ratio)
        else:
            print("[*] Can bang o muc chap nhan duoc (ty le %.1fx)." % ratio)

    # dem window ATTACK duoi nguong luat -> cho ML co the hon luat o Phase 2
    sub = att = 0
    with open(OUT_CSV) as f:
        for row in csv.DictReader(f):
            if row["label"] != "BENIGN":
                att += 1
                if float(row["pps"]) < RULE_PPS and float(row["syn_s"]) < RULE_SYN:
                    sub += 1
    print("[*] Window ATTACK duoi nguong luat (pps<%d va syn<%d): %d / %d (%.1f%%)"
          % (RULE_PPS, RULE_SYN, sub, att, 100.0 * sub / max(att, 1)))
    print("    -> day la cac window luat BO SOT; Phase 2 se kiem tra ML co bat duoc khong.")


if __name__ == "__main__":
    main()
