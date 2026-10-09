#!/usr/bin/env python3
"""Phat hien DoS/DDoS realtime: threshold + entropy. Chi dung trong lab."""
import argparse, time, math, collections, threading, json, sys, os, signal
from scapy.all import sniff, IP, TCP

# ====== bo dem cho moi cua so thoi gian ======
VICTIM = None   # neu set: chi dem goi INBOUND (dst == victim), bo qua goi victim tu tra ve
lock = threading.Lock()
win = {
    "packets": 0,
    "syn": 0,
    "ack": 0,
    "src_ip": collections.Counter(),   # dem goi theo source IP  -> entropy nguon
    "dst_port": collections.Counter(), # dem goi theo dest port  -> entropy dich
}

def reset_window():
    return {"packets":0,"syn":0,"ack":0,"src_ip":collections.Counter(),"dst_port":collections.Counter()}

def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        p = c / total
        h -= p * math.log2(p)
    return h

def ewma_update(st, pps, syn, alpha):
    # EWMA cho trung binh (mu) + do lech tuyet doi trung binh (MAD), tung chi so.
    # Cap nhat MAD truoc (dung mu cu) roi moi cap nhat mu.
    st["mad_pps"] = alpha * abs(pps - st["mu_pps"]) + (1 - alpha) * st["mad_pps"]
    st["mu_pps"]  = alpha * pps + (1 - alpha) * st["mu_pps"]
    st["mad_syn"] = alpha * abs(syn - st["mu_syn"]) + (1 - alpha) * st["mad_syn"]
    st["mu_syn"]  = alpha * syn + (1 - alpha) * st["mu_syn"]

def on_packet(pkt):
    if IP not in pkt:
        return
    # Detector sniff o netns cua victim => thay ca 2 chieu. Chi giu goi INBOUND
    # (dst == victim) de khong dem gan gói victim tu tra ve (SYN-ACK) thanh nguon.
    if VICTIM and pkt[IP].dst != VICTIM:
        return
    with lock:
        win["packets"] += 1
        win["src_ip"][pkt[IP].src] += 1
        if TCP in pkt:
            f = pkt[TCP].flags
            win["dst_port"][pkt[TCP].dport] += 1
            if f & 0x02:  # SYN
                win["syn"] += 1
            if f & 0x10:  # ACK
                win["ack"] += 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--interval", type=float, default=1.0, help="do dai cua so (giay)")
    ap.add_argument("--pps", type=int, default=200, help="nguong packet/s")
    ap.add_argument("--syn", type=int, default=100, help="nguong SYN/s")
    ap.add_argument("--victim", default="172.30.0.10",
                    help="chi dem goi inbound toi victim (src!=victim). De rong '' = dem tat ca")
    ap.add_argument("--adaptive", action="store_true",
                    help="dung nguong THICH NGHI (EWMA) thay cho nguong co dinh")
    ap.add_argument("--alpha", type=float, default=0.2, help="he so lam min EWMA (0..1)")
    ap.add_argument("--k", type=float, default=4.0, help="do nhay: nguong = baseline + k*MAD")
    ap.add_argument("--warmup", type=int, default=8, help="so cua so hoc baseline truoc khi canh bao")
    ap.add_argument("--stream", action="store_true",
                    help="in 1 JSON/dong moi window ra stdout (cho dashboard); tat bang text")
    ap.add_argument("--csv", default="", help="ghi log ra file CSV neu co")
    ap.add_argument("--ml", default="",
                    help="duong dan model .joblib (train_window.py) de phan loai ML SONG SONG voi luat")
    ap.add_argument("--engine", choices=["scapy", "ebpf"], default="scapy",
                    help="backend dem goi: scapy (mac dinh) hoac ebpf (XDP, chinh xac o line-rate)")
    args = ap.parse_args()

    global VICTIM
    VICTIM = args.victim or None

    # Nap model ML neu co --ml. Fail RO (thoat han) neu thieu file / thieu sklearn-joblib / bundle sai,
    # de khong chay nham che do "co --ml nhung ML im lang".
    ml = None
    if args.ml:
        try:
            import joblib
            b = joblib.load(args.ml)
            ml = {"model": b["model"], "features": list(b["features"]), "labels": list(b["labels"])}
        except Exception as e:
            sys.stderr.write("[X] Khong nap duoc model ML tu '%s': %s\n"
                             "    (thieu file? chua cai scikit-learn/joblib trong container? bundle sai?)\n"
                             % (args.ml, e))
            sys.stderr.flush()
            os._exit(4)

    if not args.stream:
        print("[*] Detector chay tren iface=%s, interval=%.1fs, nguong pps=%d syn=%d, victim=%s, engine=%s"
              % (args.iface, args.interval, args.pps, args.syn, VICTIM or "(tat ca)", args.engine))
        if args.adaptive:
            print("[*] Che do NGUONG THICH NGHI (EWMA): alpha=%.2f k=%.1f warmup=%ds, san toi thieu pps>=%d syn>=%d"
                  % (args.alpha, args.k, args.warmup, args.pps, args.syn))
        if ml:
            print("[*] ML song song: model=%s | lop=%s" % (args.ml, ml["labels"]))
        print("%-8s %8s %8s %8s %10s %10s   %s" %
              ("time","pkts/s","syn/s","ack/s","H(src)","H(dport)","ALERT (luat) | ML" if ml else "ALERT"))
    csvf = open(args.csv, "w") if args.csv else None
    if csvf:
        csvf.write("time,pps,syn_s,ack_s,h_src,h_dport,n_src,alert" +
                   (",ml_verdict,ml_conf" if ml else "") + "\n")

    # ====== chon BACKEND dem goi ======
    # Hai backend cung tra ve (packets, syn, ack, src_counter, dport_counter) cho moi cua so,
    # phan con lai cua detector (luat, --adaptive, --ml, --stream, --csv) GIU NGUYEN.
    ebpf = None
    if args.engine == "ebpf":
        # eBPF/XDP: dem chinh xac o line-rate (scapy rot goi khi pps cao). Fail RO neu nap/attach loi.
        try:
            from ebpf_counter import EbpfCounter
            ebpf = EbpfCounter(args.iface, VICTIM)
        except Exception as e:
            sys.stderr.write("[X] Khong khoi tao duoc engine eBPF tren iface=%s: %s\n"
                             "    (thieu bcc/kernel headers? thieu CAP_BPF/NET_ADMIN? XDP-generic khong attach duoc?)\n"
                             % (args.iface, e))
            sys.stderr.flush()
            os._exit(5)
        def snapshot():
            return ebpf.snapshot()
    else:
        # scapy: sniff o thread rieng. Fail RO neu sniff loi (vd netns gay sau khi recreate victim).
        def sniff_loop():
            try:
                sniff(iface=args.iface, prn=on_packet, store=0)
            except Exception as e:
                sys.stderr.write("[X] sniff that bai tren iface=%s: %s\n"
                                 "    (netns co the da gay - hay 'docker compose up -d --force-recreate')\n"
                                 % (args.iface, e))
                sys.stderr.flush()
                os._exit(3)
        threading.Thread(target=sniff_loop, daemon=True).start()
        def snapshot():
            with lock:
                snap_src = win["src_ip"].copy()
                snap_dport = win["dst_port"].copy()
                pkts, syn, ack = win["packets"], win["syn"], win["ack"]
                for k, v in reset_window().items():
                    win[k] = v
            return pkts, syn, ack, snap_src, snap_dport

    # Don dep khi bi dung (SIGTERM/SIGINT): go XDP ra khoi eth0 de khong de lai chuong trinh treo.
    def _cleanup(*_):
        if ebpf:
            ebpf.stop()
        os._exit(0)
    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    ew = {"mu_pps": 0.0, "mad_pps": 0.0, "mu_syn": 0.0, "mad_syn": 0.0}  # trang thai EWMA
    wcount = 0

    while True:
        time.sleep(args.interval)
        packets, syn, ack, snap_src, snap_dport = snapshot()

        pps = packets / args.interval
        syn_s = syn / args.interval
        ack_s = ack / args.interval
        h_src = entropy(snap_src)
        h_dport = entropy(snap_dport)
        n_src = len(snap_src)

        # ====== ra quyet dinh ======
        if args.adaptive:
            # nguong dong = baseline (EWMA) + k*MAD, nhung khong thap hon san --pps/--syn
            wcount += 1
            thr_pps = max(ew["mu_pps"] + args.k * ew["mad_pps"], args.pps)
            thr_syn = max(ew["mu_syn"] + args.k * ew["mad_syn"], args.syn)
            triggered = wcount > args.warmup and (pps > thr_pps or syn_s > thr_syn)
            if not triggered:   # chi hoc baseline khi KHONG tan cong (tranh nhiem doc baseline)
                ewma_update(ew, pps, syn_s, args.alpha)
        else:
            thr_pps, thr_syn = args.pps, args.syn
            triggered = pps >= thr_pps or syn_s >= thr_syn

        alert = ""
        verdict = None
        syn_flood = False
        if triggered:
            # co flood -> phan loai dua vao so nguon + entropy nguon
            verdict = "DDoS" if n_src >= 2 else "DoS"
            syn_flood = (syn_s >= thr_syn and ack_s < syn_s * 0.2)
            if verdict == "DDoS":
                alert = "!! DDoS (nhieu nguon, H_src=%.2f, n=%d)" % (h_src, n_src)
            else:
                alert = "!! DoS  (it nguon, H_src=%.2f, n=%d)" % (h_src, n_src)
            if syn_flood:
                alert += " [SYN flood]"

        # ====== ML song song (neu co --ml) ======
        # Dung vector dac trung DUNG THU TU model da luu; tinh 2 ty le dan xuat giong luc train.
        ml_verdict, ml_conf = None, None
        if ml:
            feat = {"pps": pps, "syn_s": syn_s, "ack_s": ack_s, "h_src": h_src,
                    "h_dport": h_dport, "n_src": n_src,
                    "syn_ratio": syn_s / max(pps, 1.0), "ack_syn_ratio": ack_s / max(syn_s, 1.0)}
            vec = [[feat[k] for k in ml["features"]]]
            ml_verdict = str(ml["model"].predict(vec)[0])
            try:
                ml_conf = float(max(ml["model"].predict_proba(vec)[0]))
            except Exception:
                ml_conf = None

        if csvf:
            row = "%s,%.0f,%.0f,%.0f,%.3f,%.3f,%d,%s" % (
                time.strftime("%H:%M:%S"), pps, syn_s, ack_s, h_src, h_dport, n_src, alert.replace(","," "))
            if ml:
                row += ",%s,%s" % (ml_verdict or "", ("%.3f" % ml_conf) if ml_conf is not None else "")
            csvf.write(row + "\n")
            csvf.flush()

        if args.stream:
            # 1 JSON/dong cho dashboard (stdout sach, de backend parse)
            print(json.dumps({
                "time": time.strftime("%H:%M:%S"),
                "pps": round(pps), "syn": round(syn_s), "ack": round(ack_s),
                "h_src": round(h_src, 3), "h_dport": round(h_dport, 3), "n_src": n_src,
                "triggered": bool(triggered), "verdict": verdict, "syn_flood": syn_flood,
                "thr_pps": round(thr_pps, 1), "thr_syn": round(thr_syn, 1),
                "ml_verdict": ml_verdict, "ml_conf": round(ml_conf, 3) if ml_conf is not None else None,
            }), flush=True)
        else:
            ml_txt = ""
            if ml:
                ml_txt = ("  | ML:%s(%.2f)" % (ml_verdict, ml_conf)) if ml_conf is not None else ("  | ML:%s" % ml_verdict)
            print("%-8s %8.0f %8.0f %8.0f %10.2f %10.2f   %s%s" %
                  (time.strftime("%H:%M:%S"), pps, syn_s, ack_s, h_src, h_dport, alert, ml_txt))

if __name__ == "__main__":
    main()
