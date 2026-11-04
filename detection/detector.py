#!/usr/bin/env python3
"""Phat hien DoS/DDoS realtime: threshold + entropy. Chi dung trong lab."""
import argparse, time, math, collections, threading, json, sys, os, signal
from scapy.all import sniff, IP, TCP, UDP

# ====== bo dem cho moi cua so thoi gian ======
VICTIM = None   # neu set: chi dem goi INBOUND (dst == victim), bo qua goi victim tu tra ve
lock = threading.Lock()
win = {
    "packets": 0,
    "syn": 0,
    "ack": 0,
    "udp": 0,                           # dem goi UDP -> nhan dang UDP flood (volumetric)
    "dns": 0,                           # dem goi UDP source-port 53 -> nhan dang DNS amplification (reflection)
    "src_ip": collections.Counter(),   # dem goi theo source IP  -> entropy nguon
    "dst_port": collections.Counter(), # dem goi theo dest port  -> entropy dich
}

def reset_window():
    return {"packets":0,"syn":0,"ack":0,"udp":0,"dns":0,"src_ip":collections.Counter(),"dst_port":collections.Counter()}

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
        elif UDP in pkt:  # volumetric L3/4: dem rieng de nhan dang UDP flood
            win["udp"] += 1
            if pkt[UDP].sport == 53:  # UDP tu port 53 = phan hoi DNS -> dau hieu DNS amplification
                win["dns"] += 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--interval", type=float, default=1.0, help="do dai cua so (giay)")
    ap.add_argument("--pps", type=int, default=200, help="nguong packet/s")
    ap.add_argument("--syn", type=int, default=100, help="nguong SYN/s")
    ap.add_argument("--ddos-min-src", type=int, default=10,
                    help="n_src >= nguong nay => DDoS ngay (rat nhieu nguon: spoof hoac nhieu may that)")
    ap.add_argument("--ddos-dom-share", type=float, default=0.8,
                    help="khi 2..min-src nguon: neu nguon lon nhat chiem < nguong nay => DDoS; "
                         "nguoc lai 1 nguon ap dao (+ nhieu nen mang that) => DoS")
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
    ap.add_argument("--block", action="store_true",
                    help="BAT closed-loop chan goi (chi voi --engine ebpf). Mac dinh TAT = detect-only")
    ap.add_argument("--block-pps", type=int, default=300,
                    help="nguong goi/giay/nguon de dua nguon vao blocklist (XDP_DROP co TTL)")
    ap.add_argument("--block-ttl", type=float, default=5.0,
                    help="TTL (giay) cua muc blocklist -> tu het han, khong chan vinh vien")
    ap.add_argument("--block-syn-rate", type=int, default=0,
                    help="token-bucket SYN toan cuc: drop SYN vuot N/giay (0=tat). De cat SYN spoof")
    ap.add_argument("--block-udp-rate", type=int, default=0,
                    help="token-bucket UDP toan cuc: drop UDP vuot N/giay (0=tat). De cat UDP flood spoof")
    ap.add_argument("--block-icmp-rate", type=int, default=0,
                    help="token-bucket ICMP toan cuc: drop ICMP vuot N/giay (0=tat). De cat ICMP flood spoof")
    args = ap.parse_args()

    global VICTIM
    VICTIM = args.victim or None

    if args.block and args.engine != "ebpf":
        sys.stderr.write("[X] --block chi dung voi --engine ebpf (scapy khong the drop goi).\n")
        sys.stderr.flush()
        os._exit(6)

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
        if args.block:
            print("[*] CHAN (closed-loop IPS): block-pps=%d ttl=%.0fs syn-rate=%s udp-rate=%s icmp-rate=%s"
                  % (args.block_pps, args.block_ttl, args.block_syn_rate or "tat",
                     args.block_udp_rate or "tat", args.block_icmp_rate or "tat"))
        print("%-8s %8s %8s %8s %8s %8s %10s %10s   %s" %
              ("time","pkts/s","syn/s","ack/s","udp/s","dns/s","H(src)","H(dport)","ALERT (luat) | ML" if ml else "ALERT"))
    csvf = open(args.csv, "w") if args.csv else None
    if csvf:
        csvf.write("time,pps,syn_s,ack_s,udp_s,dns_s,h_src,h_dport,n_src,alert" +
                   (",ml_verdict,ml_conf" if ml else "") +
                   (",blocked_src,blocked_pps" if args.block else "") + "\n")

    # ====== chon BACKEND dem goi ======
    # Hai backend cung tra ve (packets, syn, ack, udp, dns, src_counter, dport_counter) cho moi cua so,
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
                pkts, syn, ack, udp, dns = win["packets"], win["syn"], win["ack"], win["udp"], win["dns"]
                for k, v in reset_window().items():
                    win[k] = v
            return pkts, syn, ack, udp, dns, snap_src, snap_dport

    # Don dep khi bi dung (SIGTERM/SIGINT): go XDP ra khoi eth0 de khong de lai chuong trinh treo.
    def _cleanup(*_):
        if ebpf:
            ebpf.stop()
        os._exit(0)
    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    if args.block and ebpf:
        ebpf.set_syn_rate(args.block_syn_rate)     # token-bucket SYN (0=tat)
        ebpf.set_udp_rate(args.block_udp_rate)     # token-bucket UDP (0=tat) - xu UDP flood spoof
        ebpf.set_icmp_rate(args.block_icmp_rate)   # token-bucket ICMP (0=tat) - xu ICMP flood spoof

    ew = {"mu_pps": 0.0, "mad_pps": 0.0, "mu_syn": 0.0, "mad_syn": 0.0}  # trang thai EWMA
    wcount = 0
    was_blocking = None
    is_blocking = args.block

    # File dieu khien dong tu dashboard web UI
    BLOCK_CTRL_FILE = "/tmp/detector_block"

    while True:
        # Kiem tra file dieu khien dong tu Dashboard
        if os.path.exists(BLOCK_CTRL_FILE):
            try:
                with open(BLOCK_CTRL_FILE, "r") as f:
                    cval = f.read().strip().lower()
                    if cval in ("1", "true", "on"):
                        is_blocking = True
                    elif cval in ("0", "false", "off"):
                        is_blocking = False
            except Exception:
                pass
        else:
            is_blocking = args.block

        # Chuyen doi trang thai phong thu
        if is_blocking != was_blocking:
            if is_blocking:
                sys.stderr.write("[*] [IPS] Closed-loop Defense ACTIVATED (XDP_DROP Active)\n")
                sys.stderr.flush()
                if ebpf:
                    syn_rate = args.block_syn_rate if args.block_syn_rate > 0 else 2000
                    udp_rate = args.block_udp_rate if args.block_udp_rate > 0 else 1000
                    icmp_rate = args.block_icmp_rate if args.block_icmp_rate > 0 else 500
                    ebpf.set_syn_rate(syn_rate)
                    ebpf.set_udp_rate(udp_rate)
                    ebpf.set_icmp_rate(icmp_rate)
            else:
                sys.stderr.write("[*] [IPS] Defense DEACTIVATED (Detect-Only Mode)\n")
                sys.stderr.flush()
                if ebpf:
                    ebpf.set_syn_rate(0)
                    ebpf.set_udp_rate(0)
                    ebpf.set_icmp_rate(0)
                    ebpf.clear_blocklist()
            was_blocking = is_blocking

        time.sleep(args.interval)
        packets, syn, ack, udp, dns, snap_src, snap_dport = snapshot()

        pps = packets / args.interval
        syn_s = syn / args.interval
        ack_s = ack / args.interval
        udp_s = udp / args.interval
        dns_s = dns / args.interval
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
        udp_flood = False
        dns_amp = False
        # ty le goi cua nguon lon nhat (do "ap dao"): ~1.0 = 1 nguon chiem gan het.
        # Tren mang that chia se, moi cua so lot vai goi nen tu may khac -> n_src phong len,
        # nhung top_share van ~1.0 => van la 1 nguon that su. Dung de tach "DoS + nhieu nen"
        # khoi DDoS that (spoof: rat nhieu nguon; nhieu may: khong nguon nao ap dao).
        total_src = sum(snap_src.values()) or 1
        top_share = (max(snap_src.values()) / total_src) if snap_src else 1.0
        if triggered:
            # co flood -> phan loai: rat nhieu nguon => DDoS ngay; vai nguon va khong ai
            # ap dao => DDoS; con lai (1 nguon ap dao + nhieu nen) => DoS.
            if n_src >= args.ddos_min_src or (n_src >= 2 and top_share < args.ddos_dom_share):
                verdict = "DDoS"
            else:
                verdict = "DoS"
            syn_flood = (syn_s >= thr_syn and ack_s < syn_s * 0.2)
            # UDP flood: volumetric UDP ap dao (udp_s vuot nguong --pps VA lon hon syn_s) ->
            # khong gan nham khi vua co SYN vua co UDP. Dung args.pps (nguong --pps) lam nguong UDP.
            udp_flood = (udp_s >= args.pps and udp_s > syn_s)
            # DNS amplification: flood phan hoi DNS (UDP source port 53) doi ve victim = reflection.
            # Dinh nghia theo dns_s vuot nguong (KHONG theo ty le dns/udp): phan hoi lon hay bi phan
            # manh IP -> eBPF dem moi manh la 1 goi UDP nen udp_s phong len, ty le dns/udp se sai lech.
            dns_amp = (dns_s >= args.pps and dns_s > syn_s)
            if verdict == "DDoS":
                alert = "!! DDoS (nhieu nguon, H_src=%.2f, n=%d, top=%.2f)" % (h_src, n_src, top_share)
            else:
                alert = "!! DoS  (it nguon, H_src=%.2f, n=%d, top=%.2f)" % (h_src, n_src, top_share)
            if syn_flood:
                alert += " [SYN flood]"
            if dns_amp:          # DNS amp uu tien hon [UDP flood] (no la UDP sport 53 chuyen biet)
                alert += " [DNS amp]"
            elif udp_flood:
                alert += " [UDP flood]"

        # ====== closed-loop CHAN (neu is_blocking; chi engine ebpf) ======
        blocked_src, blocked_pps = 0, 0
        if is_blocking and ebpf:
            # nguon nao vuot nguong trong cua so nay -> dua vao blocklist (TTL); roi don muc het han.
            hot = [ip for ip, c in snap_src.items() if c / args.interval > args.block_pps]
            if hot:
                ebpf.block_sources(hot, args.block_ttl)
            ebpf.expire_blocklist()
            blocked_src = ebpf.blocked_src_count()
            blocked_pps = ebpf.last_blocked / args.interval

        # ====== ML song song (neu co --ml) ======
        # Dung vector dac trung DUNG THU TU model da luu; cong thuc KHOP window_features.py
        # (nguon chan ly dung chung voi bo trich pcap luc train). Cung cap du 10 FEATURES hien tai;
        # vec chi lay theo ml["features"] nen van tuong thich model cu (8 feature, bo udp_s/rate_per_src).
        ml_verdict, ml_conf = None, None
        if ml:
            feat = {"pps": pps, "syn_s": syn_s, "ack_s": ack_s, "udp_s": udp_s,
                    "h_src": h_src, "h_dport": h_dport, "n_src": n_src,
                    "syn_ratio": syn_ratio, "ack_syn_ratio": ack_syn_ratio,
                    "rate_per_src": pps / max(n_src, 1)}
            vec = [[feat[k] for k in ml["features"]]]
            ml_verdict = str(ml["model"].predict(vec)[0])
            try:
                ml_conf = float(max(ml["model"].predict_proba(vec)[0]))
            except Exception:
                ml_conf = None

        if csvf:
            row = "%s,%.0f,%.0f,%.0f,%.0f,%.0f,%.3f,%.3f,%d,%s" % (
                time.strftime("%H:%M:%S"), pps, syn_s, ack_s, udp_s, dns_s, h_src, h_dport, n_src, alert.replace(","," "))
            if ml:
                row += ",%s,%s" % (ml_verdict or "", ("%.3f" % ml_conf) if ml_conf is not None else "")
            if is_blocking:
                row += ",%d,%.0f" % (blocked_src, blocked_pps)
            csvf.write(row + "\n")
            csvf.flush()

        syn_ratio = round(syn_s / max(pps, 1.0), 3)
        ack_syn_ratio = round(ack_s / max(syn_s, 1.0), 3)

        if args.stream:
            # Dinh dang IP (ho tro ca str scapy lan int network-order tu ebpf)
            def _fmt_ip(ip):
                if isinstance(ip, int):
                    import socket, struct
                    try:
                        return socket.inet_ntoa(struct.pack("I", ip))
                    except Exception:
                        return str(ip)
                return str(ip)

            top_sources = [
                {"ip": _fmt_ip(ip), "pps": round(c / args.interval), "count": c}
                for ip, c in snap_src.most_common(10)
            ]

            # 1 JSON/dong cho dashboard (stdout sach, de backend parse)
            print(json.dumps({
                "time": time.strftime("%H:%M:%S"),
                "pps": round(pps), "syn": round(syn_s), "ack": round(ack_s), "udp": round(udp_s),
                "dns": round(dns_s),
                "h_src": round(h_src, 3), "h_dport": round(h_dport, 3), "n_src": n_src,
                "syn_ratio": syn_ratio, "ack_syn_ratio": ack_syn_ratio,
                "rate_per_src": round(pps / max(n_src, 1), 1),
                "triggered": bool(triggered), "verdict": verdict or "BENIGN",
                "syn_flood": syn_flood, "udp_flood": udp_flood, "dns_amp": dns_amp,
                "thr_pps": round(thr_pps, 1), "thr_syn": round(thr_syn, 1),
                "ml_verdict": ml_verdict, "ml_conf": round(ml_conf, 3) if ml_conf is not None else None,
                "block_active": bool(is_blocking),
                "blocked_src": blocked_src, "blocked_pps": round(blocked_pps),
                "top_sources": top_sources,
            }), flush=True)
        else:
            ml_txt = ""
            if ml:
                ml_txt = ("  | ML:%s(%.2f)" % (ml_verdict, ml_conf)) if ml_conf is not None else ("  | ML:%s" % ml_verdict)
            blk_txt = ("  | BLOCK src=%d drop=%.0fpps" % (blocked_src, blocked_pps)) if is_blocking else ""
            print("%-8s %8.0f %8.0f %8.0f %8.0f %8.0f %10.2f %10.2f   %s%s%s" %
                  (time.strftime("%H:%M:%S"), pps, syn_s, ack_s, udp_s, dns_s, h_src, h_dport, alert, ml_txt, blk_txt))

if __name__ == "__main__":
    main()
