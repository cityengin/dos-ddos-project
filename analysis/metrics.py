#!/usr/bin/env python3
"""Tinh metric danh gia detector tu CSV. Chi dung trong lab.

- Tach cac episode (pps>0) = cua so tan cong (ground truth theo luu luong).
- Voi moi episode: detection time, do phu alert, nhan quan sat, so sanh voi nhan mong doi.
- False positive = so giay co alert nhung NGOAI moi episode (vd tren baseline.csv).
- False negative = so giay TRONG episode nhung khong co alert.

Vi du:
  python analysis/metrics.py detection/attack.csv --truth DoS,DDoS,DDoS
  python analysis/metrics.py detection/baseline.csv        # ky vong 0 alert
"""
import argparse, csv, datetime as dt


def parse_time(s):
    return dt.datetime.strptime(s.strip(), "%H:%M:%S")


def load(path):
    rows = list(csv.DictReader(open(path)))
    t0 = parse_time(rows[0]["time"])
    out = []
    for r in rows:
        t = parse_time(r["time"])
        if t < t0:
            t += dt.timedelta(days=1)
        out.append({
            "sec": (t - t0).total_seconds(), "time": r["time"].strip(),
            "pps": float(r["pps"]), "syn": float(r["syn_s"]), "ack": float(r["ack_s"]),
            "h_src": float(r["h_src"]), "n_src": int(r["n_src"]),
            "alert": r["alert"].strip(),
        })
    return out


def episodes(rows, gap=1):
    eps, start, hole = [], None, 0
    for i, r in enumerate(rows):
        if r["pps"] > 0:
            if start is None:
                start = i
            hole = 0
        elif start is not None:
            hole += 1
            if hole > gap:
                eps.append((start, i - hole)); start = None
    if start is not None:
        eps.append((start, len(rows) - 1))
    return eps


def observed_label(seg):
    """Nhan da so tu cac dong co alert trong episode."""
    ddos = sum(1 for r in seg if "DDoS" in r["alert"])
    dos = sum(1 for r in seg if r["alert"] and "DDoS" not in r["alert"] and "DoS" in r["alert"])
    syn = any("SYN flood" in r["alert"] for r in seg)
    if ddos == 0 and dos == 0:
        return None, syn
    return ("DDoS" if ddos >= dos else "DoS"), syn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--truth", default="", help="nhan mong doi moi episode, vd: DoS,DDoS,DDoS")
    ap.add_argument("--gap", type=int, default=1)
    args = ap.parse_args()

    rows = load(args.csv)
    eps = episodes(rows, args.gap)
    truth = [t.strip() for t in args.truth.split(",")] if args.truth else []

    in_ep = set()
    for s, e in eps:
        in_ep.update(range(s, e + 1))
    fp = sum(1 for i, r in enumerate(rows) if r["alert"] and i not in in_ep)

    print(f"File: {args.csv}   tong={len(rows)}s   episodes={len(eps)}   FP(alert ngoai tan cong)={fp}")
    print("-" * 108)
    print(f"{'ep':>2} {'bat dau':>8} {'dur':>4} {'detect(s)':>9} {'cover':>6} "
          f"{'pps_max':>8} {'syn_max':>7} {'ack_max':>7} {'n_src':>6} {'H_src':>6} "
          f"{'quan sat':>10} {'mong doi':>9} {'ket qua':>8}")
    print("-" * 108)

    correct = 0
    for k, (s, e) in enumerate(eps):
        seg = rows[s:e + 1]
        dur = len(seg)
        first_alert = next((r["sec"] for r in seg if r["alert"]), None)
        detect = "-" if first_alert is None else f"{first_alert - seg[0]['sec']:.0f}"
        alert_rows = sum(1 for r in seg if r["alert"])
        cover = f"{alert_rows}/{dur}"
        lab, syn = observed_label(seg)
        lab_show = (lab or "-") + ("+SYN" if syn else "")
        exp = truth[k] if k < len(truth) else "-"
        if exp != "-":
            ok = (lab == exp)
            correct += ok
            res = "OK" if ok else "SAI"
        else:
            res = "-"
        print(f"{chr(ord('A')+k):>2} {seg[0]['time']:>8} {dur:>4} {detect:>9} {cover:>6} "
              f"{max(r['pps'] for r in seg):>8.0f} {max(r['syn'] for r in seg):>7.0f} "
              f"{max(r['ack'] for r in seg):>7.0f} {max(r['n_src'] for r in seg):>6} "
              f"{max(r['h_src'] for r in seg):>6.2f} {lab_show:>10} {exp:>9} {res:>8}")

    print("-" * 108)
    # FN: tong so giay trong episode ma khong co alert
    fn = sum(1 for i in in_ep if not rows[i]["alert"])
    print(f"False negative (giay trong tan cong khong bao dong): {fn}")
    if truth:
        print(f"Do chinh xac phan loai: {correct}/{len(eps)}")


if __name__ == "__main__":
    main()
