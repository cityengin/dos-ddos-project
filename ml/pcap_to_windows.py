#!/usr/bin/env python3
"""Trich dac trung muc-CUA-SO tu PCAP (offline) + gan nhan theo TIMELINE. Chi dung trong lab.

Thay cho duong ghi-thang-CSV cu (build_window_dataset.py van giu lam fallback). Diem khac:
  - Doc .pcap (tcpdump -s 100) bang scapy PcapReader (streaming).
  - CUA SO TRUOT GOI DAU: window=1.0s, stride=0.5s (gan nhau chong ~50% goi).
  - Dac trung tinh bang detection/window_features.py -> GIONG HET detector live (rang buoc 4).
  - GAN NHAN THEO THOI GIAN (khong theo pps==0): cua so giao thoi gian voi mot pha tan cong
    (=> co goi tan cong trong cua so) -> gan nhan pha do (DoS/DDoS); nguoc lai BENIGN.
    Day la luat "trong cua so co goi tan cong thi gan attack" (uu tien phat hien som).
  - avg_pkt_size lay theo ip.len (kich thuoc tang IP that), KHONG theo capture-len (bi snaplen cat).

LORO: moi pcap = mot "run" (dung --run). Ghi noi (append) vao ml/data/windows_pcap.csv.

Chay tren HOST (can scapy):
  python3 ml/pcap_to_windows.py detection/cap/s1.pcap --timeline detection/cap/s1.timeline --run s1
"""
import argparse
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))   # de import window_features (dung chung)
import window_features as wf   # noqa: E402

from scapy.all import PcapReader, IP, TCP, UDP   # noqa: E402

OUT_DEFAULT = os.path.join(ROOT, "ml", "data", "windows_pcap.csv")


def read_timeline(path):
    """Doc timeline -> list khoang pha TAN CONG (start, end, label) voi label != BENIGN.
    Cac dong: '<epoch> PHASE_START <name> <label>' / '<epoch> PHASE_END <name> <label>'."""
    starts = {}
    intervals = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 4:
                continue
            ts, ev, name, label = float(parts[0]), parts[1], parts[2], parts[3]
            if ev == "PHASE_START":
                starts[name] = (ts, label)
            elif ev == "PHASE_END" and name in starts:
                s, lab = starts.pop(name)
                if lab != "BENIGN":           # chi khoang tan cong moi quyet dinh nhan attack
                    intervals.append((s, ts, lab))
    return intervals


def label_for(wstart, wend, intervals):
    # Cua so [wstart,wend) giao khoang tan cong nao -> nhan pha do; khong giao -> BENIGN.
    best, best_ov = "BENIGN", 0.0
    for s, e, lab in intervals:
        ov = min(wend, e) - max(wstart, s)
        if ov > 0 and ov > best_ov:          # chon khoang giao nhieu nhat (cac pha khong chong nhau)
            best, best_ov = lab, ov
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--timeline", required=True)
    ap.add_argument("--run", required=True, help="ten run (1 pcap = 1 run cho LORO)")
    ap.add_argument("--victim", default="172.30.0.10", help="chi dem goi inbound toi victim")
    ap.add_argument("--window", type=float, default=1.0, help="do dai cua so (giay)")
    ap.add_argument("--stride", type=float, default=0.5, help="buoc truot (giay)")
    ap.add_argument("--out", default=OUT_DEFAULT)
    args = ap.parse_args()

    nb = round(args.window / args.stride)
    if abs(nb * args.stride - args.window) > 1e-9:
        sys.exit("[X] window phai la boi so cua stride (vd 1.0/0.5=2).")

    intervals = read_timeline(args.timeline)
    victim = args.victim or None

    # ===== gom goi vao cac bucket rong = stride (streaming) =====
    buckets = {}          # idx -> wf.new_counters()
    t0 = None
    max_idx = -1
    n_pkt = 0
    for pkt in PcapReader(args.pcap):
        if IP not in pkt:
            continue
        t = float(pkt.time)
        if t0 is None:
            t0 = t
        idx = int((t - t0) // args.stride)
        if idx < 0:
            continue
        c = buckets.get(idx)
        if c is None:
            c = buckets[idx] = wf.new_counters()
        ip = pkt[IP]
        if TCP in pkt:
            proto, flags, dport = wf.PROTO_TCP, int(pkt[TCP].flags), int(pkt[TCP].dport)
        elif UDP in pkt:
            proto, flags, dport = wf.PROTO_UDP, None, int(pkt[UDP].dport)
        else:
            proto, flags, dport = int(ip.proto), None, 0
        wf.add_packet(c, ip.src, ip.dst, proto, flags, dport, int(ip.len), victim)
        if idx > max_idx:
            max_idx = idx
        n_pkt += 1

    if t0 is None:
        sys.exit("[X] pcap rong hoac khong co goi IP: %s" % args.pcap)

    # ===== cua so truot: window i gom nb bucket [i, i+nb) =====
    exists = os.path.exists(args.out)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    header = ["time", "run", "label"] + wf.EXTRACT
    n_win = 0
    counts = {}
    with open(args.out, "a", newline="") as fo:
        w = csv.writer(fo, lineterminator="\n")
        if not exists:
            w.writerow(header)
        for i in range(0, max_idx - nb + 2):
            wc = wf.merge_counters([buckets[j] for j in range(i, i + nb) if j in buckets])
            feats = wf.features_from_counters(wc, args.window)
            wstart = t0 + i * args.stride
            label = label_for(wstart, wstart + args.window, intervals)
            row = ["%.3f" % wstart, args.run, label]
            for k in wf.EXTRACT:
                v = feats[k]
                row.append(str(int(v)) if k in ("n_src",) else "%.4f" % v)
            w.writerow(row)
            counts[label] = counts.get(label, 0) + 1
            n_win += 1

    print("[*] run=%s: %d goi -> %d cua so (%s) -> %s"
          % (args.run, n_pkt, n_win, dict(sorted(counts.items())), os.path.relpath(args.out, ROOT)))
    print("    dac trung EXTRACT (%d): %s" % (len(wf.EXTRACT), wf.EXTRACT))


if __name__ == "__main__":
    main()
