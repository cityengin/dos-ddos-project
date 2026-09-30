#!/usr/bin/env python3
"""Phat hien DoS/DDoS realtime: threshold + entropy. Chi dung trong lab."""
import argparse, time, math, collections, threading
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
    ap.add_argument("--csv", default="", help="ghi log ra file CSV neu co")
    args = ap.parse_args()

    global VICTIM
    VICTIM = args.victim or None

    print("[*] Detector chay tren iface=%s, interval=%.1fs, nguong pps=%d syn=%d, victim=%s"
          % (args.iface, args.interval, args.pps, args.syn, VICTIM or "(tat ca)"))
    print("%-8s %8s %8s %8s %10s %10s   %s" %
          ("time","pkts/s","syn/s","ack/s","H(src)","H(dport)","ALERT"))
    csvf = open(args.csv, "w") if args.csv else None
    if csvf:
        csvf.write("time,pps,syn_s,ack_s,h_src,h_dport,n_src,alert\n")

    # sniff chay o thread rieng, main loop in bao cao moi interval
    t = threading.Thread(target=lambda: sniff(iface=args.iface, prn=on_packet, store=0), daemon=True)
    t.start()

    while True:
        time.sleep(args.interval)
        with lock:
            snap = win.copy()
            snap_src = win["src_ip"].copy()
            snap_dport = win["dst_port"].copy()
            for k,v in reset_window().items():
                win[k] = v

        pps = snap["packets"] / args.interval
        syn_s = snap["syn"] / args.interval
        ack_s = snap["ack"] / args.interval
        h_src = entropy(snap_src)
        h_dport = entropy(snap_dport)
        n_src = len(snap_src)

        # ====== ra quyet dinh ======
        alert = ""
        if pps >= args.pps or syn_s >= args.syn:
            # co flood -> phan loai dua vao so nguon + entropy nguon
            if n_src >= 2:
                alert = "!! DDoS (nhieu nguon, H_src=%.2f, n=%d)" % (h_src, n_src)
            else:
                alert = "!! DoS  (it nguon, H_src=%.2f, n=%d)" % (h_src, n_src)
            if syn_s >= args.syn and ack_s < syn_s * 0.2:
                alert += " [SYN flood]"
                
        if csvf:
            csvf.write("%s,%.0f,%.0f,%.0f,%.3f,%.3f,%d,%s\n" %
                       (time.strftime("%H:%M:%S"), pps, syn_s, ack_s, h_src, h_dport, n_src,
                        alert.replace(","," ")))
            csvf.flush()

        print("%-8s %8.0f %8.0f %8.0f %10.2f %10.2f   %s" %
              (time.strftime("%H:%M:%S"), pps, syn_s, ack_s, h_src, h_dport, alert))

if __name__ == "__main__":
    main()
